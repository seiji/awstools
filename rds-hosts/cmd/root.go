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
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds"
)

var timeout time.Duration

var rootCmd = &cobra.Command{
	Use:   "rds-hosts",
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

		svc := rds.New(sess)
		req := &rds.DescribeDBInstancesInput{}
		var res *rds.DescribeDBInstancesOutput
		if res, err = svc.DescribeDBInstances(req); err != nil {
			return
		}

		for _, i := range res.DBInstances {
			fmt.Printf("%s\t%s\n", *i.Endpoint.Address, *i.DBInstanceIdentifier)
		}
		return
	},
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
