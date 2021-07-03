package main

import (
	"fmt"
	"os"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

const (
	netlinkCustom = 31
)

func main() {
	msg := "Hello from Go"
	if len(os.Args) > 1 && os.Args[1] != "" {
		msg = os.Args[1]
	}
	if len(msg) > 1023 {
		fmt.Println("no more than 1023 characters can be send to kernel")
		return
	}

	conn, err := netlink.Dial(netlinkCustom, nil)
	if err != nil {
		fmt.Println("failed to dial netlink, err:", err)
		return
	}

	data := make([]byte, 4+len(msg)+1)
	nlenc.PutUint32(data[:4], uint32(len(msg)+1))
	copy(data[4:], msg)

	fmt.Println("Send to kernel:", msg)

	var nlmsg netlink.Message
	nlmsg.Data = data

	msgs, err := conn.Execute(nlmsg)
	if err != nil {
		fmt.Println("failed to send netlink message, err:", err)
		return
	}
	if len(msgs) == 0 {
		fmt.Println("no response message")
		return
	}

	nlmsg = msgs[0]
	result := nlenc.Uint32(nlmsg.Data[:4])
	if result != 1 {
		fmt.Printf("got unspected result from kernel, result: 0x%0x\n", result)
		return
	}

	fmt.Println(string(nlmsg.Data[4:]))
}
