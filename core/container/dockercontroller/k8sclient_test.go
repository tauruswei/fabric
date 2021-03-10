package dockercontroller

import (
	"encoding/json"
	"testing"
)

var uploads = map[string][]byte{
	"/111/22/33/4.pem": []byte("ddddd"),
	"/111/22/33/5.pem": []byte("ccccc"),
}

func Test_getDeployVolumnMount(t *testing.T) {
	vm := getDeployVolumeMount("hello-my-volumes", uploads)
	b, _ := json.Marshal(vm)
	t.Logf("bb: %v", string(b))
}

func Test_getSecret_without_labels(t *testing.T) {
	s := getSecret("demo", "demo-1", nil, uploads)
	b, _ := json.Marshal(s)
	t.Logf("bb: %v", string(b))
}

func Test_getSecret_with_labels(t *testing.T) {
	s := getSecret("demo", "demo-1", map[string]string{"app": "my-app", "demo": "my-demo"}, uploads)
	b, _ := json.Marshal(s)
	t.Logf("bb: %v", string(b))
}
func Test_getSecret_without_uploads(t *testing.T) {
	s := getSecret("demo", "demo-1", map[string]string{"app": "my-app", "demo": "my-demo"}, nil)
	b, _ := json.Marshal(s)
	t.Logf("bb: %v", string(b))
}

var defaultLables = map[string]string{"app": "my-app", "demo": "my-demo"}

func Test_getDeploy(t *testing.T) {
	/*
		getDeploy(ns, containerID, imageID, args, env, labels, affinityKey, affinityValue,
			fileUploads, imagePullPolicy)
	*/
	d := getPod("demo", "demo-1", "myImage", []string{"peer", "node", "start"},
		[]string{"CORE_AAA_BB=xxxbbb", "CORE_BBB_CC=bbbyyy"},
		defaultLables, "", "", uploads, "")

	b, _ := json.Marshal(d)
	t.Logf("bb: %v", string(b))
}
