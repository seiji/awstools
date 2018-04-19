// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

var timeout time.Duration

var rootCmd = &cobra.Command{
	Use:   "ec2-hosts",
	Short: "Generate hosts file from instances",
	Long: `Generate hosts file between instance name and public_ip or private_ip
`,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var sess *session.Session
		var creds *credentials.Credentials
		creds = credentials.NewEnvCredentials()
		if _, err = creds.Get(); err != nil {
			var val interface{}
			if val = viper.Get("AWS_PROFILE"); val != nil {
				creds = credentials.NewSharedCredentials("", val.(string))
			}
		}
		if _, err = creds.Get(); err != nil {
			return
		}

		cfg := aws.NewConfig().WithCredentials(creds)
		if sess, err = session.NewSession(cfg); err != nil {
			return
		}

		svc := ec2.New(sess)
		req := &ec2.DescribeInstancesInput{}
		var res *ec2.DescribeInstancesOutput
		if res, err = svc.DescribeInstances(req); err != nil {
			return
		}

		instances := make(map[*net.IP]*ec2.Instance, 0)
		var key string

		for _, r := range res.Reservations {
			for _, i := range r.Instances {
				if *i.State.Name != "running" {
					continue
				}
				if key = InstancePublicIp(i); key != "" {
					ip := net.ParseIP(key)
					instances[&ip] = i
				}
			}
		}

		for _, pubIp := range SortedIpKeys(instances) {
			fmt.Printf(
				"%s\t%s\n",
				pubIp,
				InstanceName(instances[pubIp]),
			)
		}
		return
	},
}

func InstanceName(i *ec2.Instance) (name string) {
	for _, t := range i.Tags {
		if *t.Key == "Name" {
			name = *t.Value
			break
		}
	}
	return
}

func InstancePublicIp(i *ec2.Instance) (publicIp string) {
	if i.PublicIpAddress != nil {
		publicIp = *i.PublicIpAddress
	}
	return
}

func SortedStringKeys(m map[string]*ec2.Instance) []string {
	i, sorted := 0, make([]string, len(m))
	for k := range m {
		sorted[i] = k
		i++
	}
	sort.Strings(sorted)
	return sorted
}

func SortedIpKeys(m map[*net.IP]*ec2.Instance) []*net.IP {
	i, sorted := 0, make([]*net.IP, len(m))
	for k := range m {
		sorted[i] = k
		i++
	}
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(*sorted[i], *sorted[j]) < 0
	})
	return sorted
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 5*time.Second, "timeout")
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func initConfig() {
	viper.AutomaticEnv()
}
