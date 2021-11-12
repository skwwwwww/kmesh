/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description:
 */

package client

import (
	xds "codehub.com/mesh/pkg/client/envoy"
	apiserver "codehub.com/mesh/pkg/client/kubernetes"
	"codehub.com/mesh/pkg/client/yaml"
	"codehub.com/mesh/pkg/option"
	"fmt"
)

type Interface interface {
	Init(config interface{})
	Start() error
}

func Start(cfg *option.ClientConfig) error {

	go yaml.Run()

	switch cfg.ClientMode {
	case option.ClientModeKube:
		go apiserver.Run(cfg)
	case option.ClientModeEnvoy:
		go xds.Run(cfg)
	default:
		return fmt.Errorf("")
	}

	return nil
}