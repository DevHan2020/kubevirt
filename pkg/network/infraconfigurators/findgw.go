package infraconfigurators

import (
	"context"
	"encoding/json"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
	v1 "kubevirt.io/client-go/api/v1"
	"kubevirt.io/client-go/log"
	"net"
)

type IPPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IPPoolSpec   `json:"spec,omitempty"`
	Status IPPoolStatus `json:"status,omitempty"`
}
type IPPoolStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// The number of exclude IPs in the IP pool
	ExcludeIPCount int `json:"excludeIPCount,omitempty"`
	// The number of IPs used in the IPPool
	Using int `json:"using,omitempty"`
	// The number of IPs available in the IPPool
	Available int `json:"available,omitempty"`
}
type IPPoolSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// The address segment of the IPPool, the cidr method indicates
	Cidr string `json:"cidr,omitempty"`
	// The spec.vlan of the IPPool. The valid range is 1-4094.
	Vlan int `json:"vlan,omitempty"`
	// Unavailable IP in the IP Pool
	ExcludeIPs []string `json:"excludeIPs,omitempty"`
	// Gateway of the IPPool
	Gateway string `json:"gateway,omitempty"`
}

func getGW(vmi *v1.VirtualMachineInstance) net.IP {
	ippoolName := vmi.Annotations["cmos.ippool"]
	virtConfig, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		log.Log.Reason(err).Errorf("cannot obtain virt to ipam client: %v\n", err)
	}
	dynamicClient := dynamic.NewForConfigOrDie(virtConfig)
	grv := schema.GroupVersionResource{Group: "ipfixed.cmos.chinamobile.com", Version: "v1alpha1", Resource: "ippools"}
	result, err := dynamicClient.Resource(grv).Get(context.Background(), ippoolName, metav1.GetOptions{})
	if err != nil {
		log.Log.Reason(err).Errorf("cannot get ippool result: %v\n", err)
	}
	data, err := result.MarshalJSON()
	if err != nil {
		log.Log.Reason(err).Errorf("cannot get MarshalJSON result: %v\n", err)
	}
	var ippool IPPool
	if err := json.Unmarshal(data, &ippool); err != nil {
		log.Log.Reason(err).Errorf("cannot get Unmarshal result: %v\n", err)
	}
	return net.ParseIP(ippool.Spec.Gateway)

}
