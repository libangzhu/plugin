package ethereum

import (
	"context"
	"fmt"
	"github.com/33cn/plugin/plugin/dapp/dex/boss/deploy/ethereum/offline"
	"github.com/33cn/plugin/plugin/dapp/dex/contracts/pancake-farm/src/cakeToken"
	"github.com/33cn/plugin/plugin/dapp/dex/contracts/pancake-farm/src/masterChef"
	"github.com/33cn/plugin/plugin/dapp/dex/contracts/pancake-farm/src/syrupBar"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
	"strings"
	"time"
)

func GetCakeBalance(owner string, pid int64) (string, error) {
	masterChefInt, err := masterChef.NewMasterChef(common.HexToAddress("0xD88654a6aAc42a7192d697a8250a93246De882C6"), ethClient)
	if nil != err {
		return "", err
	}
	ownerAddr := common.HexToAddress(owner)
	opts := &bind.CallOpts{
		From:    ownerAddr,
		Context: context.Background(),
	}
	amount, err := masterChefInt.PendingCake(opts, big.NewInt(pid), ownerAddr)
	if nil != err {
		return "", err
	}
	return amount.String(), nil
}

func DeployFarm() error {
	_ = recoverBinancePrivateKey()
	//1st step to deploy factory
	auth, err := PrepareAuth(privateKey, deployerAddr)
	if nil != err {
		return err
	}

	cakeTokenAddr, deploycakeTokenTx, _, err := cakeToken.DeployCakeToken(auth, ethClient)
	if nil != err {
		panic(fmt.Sprintf("Failed to DeployCakeToken with err:%s", err.Error()))
		return err
	}

	{
		fmt.Println("\nDeployCakeToken tx hash:", deploycakeTokenTx.Hash().String())
		timeout := time.NewTimer(300 * time.Second)
		oneSecondtimeout := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-timeout.C:
				panic("DeployCakeToken timeout")
			case <-oneSecondtimeout.C:
				_, err := ethClient.TransactionReceipt(context.Background(), deploycakeTokenTx.Hash())
				if err == ethereum.NotFound {
					fmt.Println("\n No receipt received yet for DeployCakeToken tx and continue to wait")
					continue
				} else if err != nil {
					panic("DeployCakeToken failed due to" + err.Error())
				}
				fmt.Println("\n Succeed to deploy DeployCakeToken with address =", cakeTokenAddr.String())
				goto deploySyrupBar
			}
		}
	}

deploySyrupBar:
	auth, err = PrepareAuth(privateKey, deployerAddr)
	if nil != err {
		return err
	}
	SyrupBarAddr, deploySyrupBarTx, _, err := syrupBar.DeploySyrupBar(auth, ethClient, cakeTokenAddr)
	if err != nil {
		panic(fmt.Sprintf("Failed to DeploySyrupBar with err:%s", err.Error()))
		return err
	}

	{
		fmt.Println("\nDeploySyrupBar tx hash:", deploySyrupBarTx.Hash().String())
		timeout := time.NewTimer(300 * time.Second)
		oneSecondtimeout := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-timeout.C:
				panic("DeploySyrupBar timeout")
			case <-oneSecondtimeout.C:
				_, err := ethClient.TransactionReceipt(context.Background(), deploySyrupBarTx.Hash())
				if err == ethereum.NotFound {
					fmt.Println("\n No receipt received yet for DeploySyrupBar tx and continue to wait")
					continue
				} else if err != nil {
					panic("DeploySyrupBar failed due to" + err.Error())
				}
				fmt.Println("\n Succeed to deploy DeploySyrupBar with address =", SyrupBarAddr.String())
				goto deployMasterchef
			}
		}
	}

deployMasterchef:
	auth, err = PrepareAuth(privateKey, deployerAddr)
	if nil != err {
		return err
	}
	//auth *bind.TransactOpts, backend bind.ContractBackend, _cake common.Address, _syrup common.Address, _devaddr common.Address, _cakePerBlock *big.Int, _startBlock *big.Int
	MasterChefAddr, deployMasterChefTx, _, err := masterChef.DeployMasterChef(auth, ethClient, cakeTokenAddr, SyrupBarAddr, deployerAddr, big.NewInt(5*1e18), big.NewInt(100))
	if err != nil {
		panic(fmt.Sprintf("Failed to DeployMasterChef with err:%s", err.Error()))
		return err
	}

	{
		fmt.Println("\nDeployMasterChef tx hash:", deployMasterChefTx.Hash().String())
		timeout := time.NewTimer(300 * time.Second)
		oneSecondtimeout := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-timeout.C:
				panic("DeployMasterChef timeout")
			case <-oneSecondtimeout.C:
				_, err := ethClient.TransactionReceipt(context.Background(), deployMasterChefTx.Hash())
				if err == ethereum.NotFound {
					fmt.Println("\n No receipt received yet for DeployMasterChef tx and continue to wait")
					continue
				} else if err != nil {
					panic("DeployMasterChef failed due to" + err.Error())
				}
				fmt.Println("\n Succeed to deploy DeployMasterChef with address =", MasterChefAddr.String())
				return nil
			}
		}
	}
	return nil
}

func AddPool2FarmHandle(masterChefAddrStr string, allocPoint int64, lpToken string, withUpdate bool, gasLimit uint64) (err error) {
	masterChefAddr := common.HexToAddress(masterChefAddrStr)
	masterChefInt, err := masterChef.NewMasterChef(masterChefAddr, ethClient)
	if nil != err {
		return err
	}

	_ = recoverBinancePrivateKey()
	//1st step to deploy factory
	auth, err := PrepareAuth(privateKey, deployerAddr)
	if nil != err {
		return err
	}

	AddPool2FarmTx, err := masterChefInt.Add(auth, big.NewInt(int64(allocPoint)), common.HexToAddress(lpToken), withUpdate)
	if err != nil {
		if strings.Contains(err.Error(), "failed to estimate gas needed") {
			fmt.Println("specific gas to create tx...")
			//指定gas大小，手动构建签名交易
			if gasLimit == 0 {
				gasLimit = 10000 * 80
			}

			parsed, err := abi.JSON(strings.NewReader(masterChef.MasterChefABI))
			input, err := parsed.Pack("add", big.NewInt(allocPoint), common.HexToAddress(lpToken), withUpdate)
			if err != nil {
				panic(err)
			}
			gasPrice, err := ethClient.SuggestGasPrice(context.Background())
			if err != nil {
				panic(err)
			}
			ntx := types.NewTransaction(auth.Nonce.Uint64(), masterChefAddr, new(big.Int), gasLimit, gasPrice, input)
			signedTx, _, err := offline.SignTx(privateKey, ntx)
			if err != nil {
				panic(err)
			}
			AddPool2FarmTx = new(types.Transaction)
			err = AddPool2FarmTx.UnmarshalBinary(common.FromHex(signedTx))
			if err != nil {
				panic(err)
			}
			//send
			err = ethClient.SendTransaction(context.Background(), AddPool2FarmTx)
			if err != nil {
				fmt.Println("auth nonce", auth.Nonce.Uint64())
				panic(err)
			}

		} else {
			panic(fmt.Sprintf("Failed to AddPool2FarmTx with err:%s", err.Error()))

		}

	}

	{
		fmt.Println("\nAddPool2FarmTx tx hash:", AddPool2FarmTx.Hash().String())
		timeout := time.NewTimer(300 * time.Second)
		oneSecondtimeout := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-timeout.C:
				panic("AddPool2FarmTx timeout")
			case <-oneSecondtimeout.C:
				_, err := ethClient.TransactionReceipt(context.Background(), AddPool2FarmTx.Hash())
				if err == ethereum.NotFound {
					fmt.Println("\n No receipt received yet for AddPool2FarmTx tx and continue to wait")
					continue
				} else if err != nil {
					panic("AddPool2FarmTx failed due to" + err.Error())
				}
				return nil
			}
		}
	}

	return nil
}

func UpdateAllocPointHandle(masterChefAddrStr string, pid, allocPoint int64, withUpdate bool) (err error) {
	masterChefAddr := common.HexToAddress(masterChefAddrStr)
	masterChefInt, err := masterChef.NewMasterChef(masterChefAddr, ethClient)
	if nil != err {
		return err
	}

	_ = recoverBinancePrivateKey()
	auth, err := PrepareAuth(privateKey, deployerAddr)
	if nil != err {
		return err
	}

	//_pid *big.Int, _allocPoint *big.Int, _withUpdate bool
	SetPool2FarmTx, err := masterChefInt.Set(auth, big.NewInt(pid), big.NewInt(allocPoint), withUpdate)
	if err != nil {
		panic(fmt.Sprintf("Failed to SetPool2FarmTx with err:%s", err.Error()))
		return err
	}

	{
		fmt.Println("\nSetPool2FarmTx tx hash:", SetPool2FarmTx.Hash().String())
		timeout := time.NewTimer(300 * time.Second)
		oneSecondtimeout := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-timeout.C:
				panic("SetPool2FarmTx timeout")
			case <-oneSecondtimeout.C:
				_, err := ethClient.TransactionReceipt(context.Background(), SetPool2FarmTx.Hash())
				if err == ethereum.NotFound {
					fmt.Println("\n No receipt received yet for SetPool2FarmTx tx and continue to wait")
					continue
				} else if err != nil {
					panic("SetPool2FarmTx failed due to" + err.Error())
				}
				return nil
			}
		}
	}
	return nil
}

func TransferOwnerShipHandle(newOwner, contract string) (err error) {
	contractAddr := common.HexToAddress(contract)
	contractInt, err := syrupBar.NewSyrupBar(contractAddr, ethClient)
	if nil != err {
		return err
	}

	_ = recoverBinancePrivateKey()
	auth, err := PrepareAuth(privateKey, deployerAddr)
	if nil != err {
		return err
	}

	//_pid *big.Int, _allocPoint *big.Int, _withUpdate bool

	newOwnerAddr := common.HexToAddress(newOwner)
	TransferOwnershipTx, err := contractInt.TransferOwnership(auth, newOwnerAddr)
	if err != nil {
		panic(fmt.Sprintf("Failed to TransferOwnership with err:%s", err.Error()))
		return err
	}

	{
		fmt.Println("\nTransferOwnership tx hash:", TransferOwnershipTx.Hash().String())
		timeout := time.NewTimer(300 * time.Second)
		oneSecondtimeout := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-timeout.C:
				panic("TransferOwnership timeout")
			case <-oneSecondtimeout.C:
				_, err := ethClient.TransactionReceipt(context.Background(), TransferOwnershipTx.Hash())
				if err == ethereum.NotFound {
					fmt.Println("\n No receipt received yet for TransferOwnership tx and continue to wait")
					continue
				} else if err != nil {
					panic("TransferOwnership failed due to" + err.Error())
				}
				return nil
			}
		}
	}

	return nil
}
