/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * Author: LemmyHuang
 * Create: 2022-01-08
 */

package controller_workload

import (
	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/controller_workload/interfaces"
	"kmesh.net/kmesh/pkg/controller_workload/workload"
	"kmesh.net/kmesh/pkg/options"
)

var config Config

func init() {
	options.Register(&config)
}

type Config struct {
	workloadConfig *workload.XdsConfig
}

// SetArgs set controller command arguments
func (c *Config) SetArgs() error {
	return workload.GetConfig().SetClientArgs()
}

func (c *Config) ParseConfig() error {
	if bpf.GetConfig().EnableKmesh || bpf.GetConfig().EnableMda || bpf.GetConfig().EnableKmeshWorkload {
		c.workloadConfig = workload.GetConfig()
	}

	return c.workloadConfig.Init()
}

func (c *Config) NewClient() (interfaces.ClientFactory, error) {
	return c.workloadConfig.NewClient()
}