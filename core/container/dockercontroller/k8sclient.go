package dockercontroller

import (
	"fmt"
	"github.com/spf13/viper"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"path/filepath"
	"strings"
)

type K8sClientSet struct {
	*kubernetes.Clientset
}

type Opt struct {
	NS   string
	Name string
}

func NewK8SClient() (*K8sClientSet, error) {

	var path string
	path = viper.GetString("vm.k8s.config")

	if len(path) == 0 {
		return nil, fmt.Errorf("k8s config path [%v] erorr", path)
	}

	configByte, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 k8sConfig [%s] error %v", path, err)
	}

	kubeConfig, err := clientcmd.NewClientConfigFromBytes(configByte)
	if err != nil {
		return nil, err
	}
	c, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	client := kubernetes.NewForConfigOrDie(c)
	if client == nil {
		return nil, fmt.Errorf("Kubernetst client is  null ")
	}

	return &K8sClientSet{client}, nil
}

func (k *K8sClientSet) createPod(imageID, containerID string, args, env []string,
	fileUploads map[string][]byte, ns, affinityKey, affinityValue, imagePullPolicy string, labels map[string]string) error {

	dockerLogger.Infof("start createPod")
	err := k.createSecret(ns, containerID, labels, fileUploads)
	if err != nil {
		return fmt.Errorf("create secret [%v] error %v", containerID, err)
	}

	_, err = k.Clientset.CoreV1().Pods(ns).Create(getPod(ns, containerID, imageID, args, env, labels, affinityKey, affinityValue,
		fileUploads, imagePullPolicy))
	if err != nil {
		dockerLogger.Warnf("Create Pods [%s][%s] erorr :%v", ns, containerID, err)
	}
	if err := k.watch(Opt{Name: containerID, NS: ns}, labels); err != nil {
		return err
	}

	return nil
}

func (k *K8sClientSet) watch(opt Opt, lables map[string]string) error {
	timeout := int64(60)

	var singleLable string
	for key, val := range lables {
		strings.Join([]string{key, val}, "=")
		break
	}

	w, err := k.Clientset.CoreV1().Pods(opt.NS).Watch(metav1.ListOptions{
		LabelSelector:  singleLable,
		Watch:          true,
		TimeoutSeconds: &timeout,
	})
	if err != nil {
		return err
	}

	for {
		e := <-w.ResultChan()
		if e.Object == nil {
			return fmt.Errorf("watch timeout")
		}
		pod, ok := e.Object.(*corev1.Pod)
		if !ok {
			return fmt.Errorf("format Job error")
		}

		if pod.Status.Phase == corev1.PodRunning {
			return nil
		}
	}
}

func (k *K8sClientSet) deletePod(del Opt) error {

	err := k.Clientset.CoreV1().Secrets(del.NS).Delete(del.Name, &metav1.DeleteOptions{})
	if err != nil {
		dockerLogger.Warnf("delete secret [%s][%s] erorr :%v", del.NS, del.Name, err)
	}

	var gracePeriod int64 = 0 // 立即删除
	return k.Clientset.CoreV1().Pods(del.NS).Delete(del.Name,
		&metav1.DeleteOptions{GracePeriodSeconds: &gracePeriod})
}

func (k *K8sClientSet) createSecret(ns, name string, labels map[string]string, uploads map[string][]byte) error {

	sec := getSecret(ns, name, labels, uploads)
	if sec != nil {
		_, err := k.Clientset.CoreV1().Secrets(ns).Create(sec)
		return err
	} else {
		return nil
	}
}

func getSecret(ns, name string, labels map[string]string, uploads map[string][]byte) *corev1.Secret {

	if len(uploads) == 0 {
		return nil
	} else {
		return &corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
				Labels:    labels,
			},
			Type: corev1.SecretTypeOpaque,
			Data: secretData(uploads),
		}
	}
}

func secretData(uploads map[string][]byte) map[string][]byte {

	var datas = make(map[string][]byte, len(uploads))
	for path, data := range uploads {
		_, name := filepath.Split(path)
		datas[name] = data
	}
	return datas
}

func getPod(ns, name, image string, args, envs []string, labels map[string]string, affinityKey, affinityValue string,
	fileUploads map[string][]byte, imagePullPolicy string) *corev1.Pod {

	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Affinity: getPodAffinity(affinityKey, affinityValue),
			Containers: []corev1.Container{{
				Name:  name,
				Image: image + ":latest",

				ImagePullPolicy: corev1.PullNever,
				Env:             getDeployEnv(envs),
				Command:         args,

				//Resources: ResourceRequirements
				VolumeMounts: getDeployVolumeMount(name, fileUploads),
			}},
			RestartPolicy: corev1.RestartPolicyNever, // fabric原生逻辑docker容器失败不重启，此处必须为Never
			Volumes:       getDeployVolumn(name, fileUploads),
		},
	}
}

func getPodAffinity(affinityKey, affinityValue string) *corev1.Affinity {
	if len(affinityKey) != 0 && len(affinityValue) != 0 {
		return &corev1.Affinity{PodAffinity: &corev1.PodAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{LabelSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key: affinityKey, Operator: metav1.LabelSelectorOpIn, Values: []string{affinityValue}}}},
					TopologyKey: "kubernetes.io/hostname",
				},
			},
			//PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
			//	Weight: 10,
			//	PodAffinityTerm: corev1.PodAffinityTerm{LabelSelector: &metav1.LabelSelector{
			//		MatchExpressions: []metav1.LabelSelectorRequirement{{
			//			Key: affinityKey, Operator: metav1.LabelSelectorOpIn, Values: []string{affinityValue}}}},
			//		TopologyKey: "kubernetes.io/hostname",
			//	}}}，
		}}
	} else {
		return nil
	}
}

func getDeployEnv(envs []string) []corev1.EnvVar {
	if len(envs) == 0 {
		return nil
	} else {
		var envars []corev1.EnvVar
		for _, env := range envs {
			kvs := strings.Split(env, "=")
			key, value := kvs[0], kvs[1]
			envars = append(envars, corev1.EnvVar{Name: key, Value: value})
		}
		return envars
	}
}

func getDeployVolumn(name string, uploads map[string][]byte) []corev1.Volume {
	if len(uploads) == 0 {
		return nil
	} else {
		var keytoPath []corev1.KeyToPath
		for path, _ := range uploads {
			_, file := filepath.Split(path)
			keytoPath = append(keytoPath, corev1.KeyToPath{Key: file, Path: file})
		}

		return []corev1.Volume{{Name: name + "-in-one", VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: name,
				Items:      keytoPath,
			},
		}}}
	}
}

func getDeployVolumeMount(name string, uploads map[string][]byte) []corev1.VolumeMount {
	if len(uploads) == 0 {
		return nil
	} else {
		return []corev1.VolumeMount{{Name: name + "-in-one", MountPath: "/etc/hyperledger/fabric", ReadOnly: true}}
	}
}
