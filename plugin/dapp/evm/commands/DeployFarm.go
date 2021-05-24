package commands

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var CakeTokenBinFile = "./ci/evm/CakeToken.bin"
var CakeTokenAbiFile = "./ci/evm/CakeToken.abi"
var SyrupBarBinFile = "./ci/evm/SyrupBar.bin"
var SyrupBarAbiFile = "./ci/evm/SyrupBar.abi"
var MasterChefBinFile = "./ci/evm/MasterChef.bin"
var MasterChefAbiFile = "./ci/evm/MasterChef.abi"

func DeployFarm(cmd *cobra.Command) error {
	caller, _ := cmd.Flags().GetString("caller")
	rpcLaddr, _ := cmd.Flags().GetString("rpc_laddr")

	txhexCakeToken, err := deployContract(cmd, CakeTokenBinFile, CakeTokenAbiFile, "", "CakeToken")
	if err != nil {
		return errors.New(err.Error())
	}

	{
		timeout := time.NewTimer(300 * time.Second)
		oneSecondtimeout := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-timeout.C:
				panic("Deploy CakeToken timeout")
			case <-oneSecondtimeout.C:
				data, _ := getTxByHashesRpc(txhexCakeToken, rpcLaddr)
				if data == "" {
					fmt.Println("No receipt received yet for Deploy CakeToken tx and continue to wait")
					continue
				} else if data != "2" {
					return errors.New("DeployPancakeFactory failed due to" + ", ty = " + data)
				}
				fmt.Println("Succeed to deploy CakeToken with address =", getContractAddr(caller, txhexCakeToken), "\\n")
				goto deploySyrupBar
			}
		}
	}

deploySyrupBar:
	txhexSyrupBar, err := deployContract(cmd, SyrupBarBinFile, SyrupBarAbiFile, getContractAddr(caller, txhexCakeToken), "SyrupBar")
	if err != nil {
		return errors.New(err.Error())
	}

	{
		timeout := time.NewTimer(300 * time.Second)
		oneSecondtimeout := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-timeout.C:
				panic("Deploy SyrupBar timeout")
			case <-oneSecondtimeout.C:
				data, _ := getTxByHashesRpc(txhexSyrupBar, rpcLaddr)
				if data == "" {
					fmt.Println("No receipt received yet for Deploy SyrupBar tx and continue to wait")
					continue
				} else if data != "2" {
					return errors.New("Deploy SyrupBar failed due to" + ", ty = " + data)
				}
				fmt.Println("Succeed to deploy SyrupBar with address =", getContractAddr(caller, txhexSyrupBar), "\\n")
				goto deployMasterChef
			}
		}
	}

deployMasterChef:
	// constructor(
	//        CakeToken _cake,
	//        SyrupBar _syrup,
	//        address _devaddr,
	//        uint256 _cakePerBlock,
	//        uint256 _startBlock
	//    )
	// masterChef.DeployMasterChef(auth, ethClient, cakeTokenAddr, SyrupBarAddr, deployerAddr, big.NewInt(5*1e18), big.NewInt(100))
	txparam := getContractAddr(caller, txhexCakeToken) + "," + getContractAddr(caller, txhexSyrupBar) + "," + caller + ", 5000000000000000000, 100"
	txhexMasterChef, err := deployContract(cmd, MasterChefBinFile, MasterChefAbiFile, txparam, "MasterChef")
	if err != nil {
		return errors.New(err.Error())
	}

	{
		timeout := time.NewTimer(300 * time.Second)
		oneSecondtimeout := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-timeout.C:
				panic("Deploy MasterChef timeout")
			case <-oneSecondtimeout.C:
				data, _ := getTxByHashesRpc(txhexMasterChef, rpcLaddr)
				if data == "" {
					fmt.Println("No receipt received yet for Deploy MasterChef tx and continue to wait")
					continue
				} else if data != "2" {
					return errors.New("Deploy MasterChef failed due to" + ", ty = " + data)
				}
				fmt.Println("Succeed to deploy MasterChef with address =", getContractAddr(caller, txhexMasterChef), "\\n")
				return nil
			}
		}
	}

	return nil
}
