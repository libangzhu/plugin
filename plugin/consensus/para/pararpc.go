// Copyright Fuzamei Corp. 2018 All Rights Reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package para

import (
	"bytes"
	"context"
	"encoding/hex"
	"github.com/33cn/chain33/common"
	"github.com/33cn/chain33/common/address"
	rty "github.com/33cn/chain33/rpc/types"
	"github.com/33cn/chain33/types"
	"github.com/gogo/protobuf/proto"
	"reflect"
)

func (client *client) GetBlockByHeight(height int64) (*types.Block, error) {
	//from blockchain db
	blockDetails, err := client.GetAPI().GetBlocks(&types.ReqBlocks{Start: height, End: height})
	if err != nil {
		plog.Error("GetBlockByHeight fail", "err", err)
		return nil, err
	}
	if 1 != int64(len(blockDetails.Items)) {
		plog.Error("GetBlockByHeight count fail", "len", len(blockDetails.Items))
		return nil, types.ErrInvalidParam
	}
	return blockDetails.Items[0].Block, nil
}

func (client *client) GetBlockHeaders(req *types.ReqBlocks) (*types.Headers, error) {
	//from blockchain db
	var headers = new(types.Headers)
	var err error
	if client.subCfg.GrpcMoudle {
		headers, err = client.grpcClient.GetHeaders(context.Background(), req)
	} else {
		var rheader rty.Headers
		err = client.jsonClient.Call("GetHeaders", req, &rheader)
		if err == nil {
			for _, rheader := range rheader.Items {
				var header types.Header
				convertHeader(rheader, &header)
				headers.Items = append(headers.Items, &header)
			}
		}
	}

	if err != nil {
		plog.Error("GetBlockHeaders fail", "err", err)
		return nil, err
	}
	count := req.End - req.Start + 1
	if int64(len(headers.Items)) != count {
		plog.Error("GetBlockHeaders", "start", req.Start, "end", req.End, "reals", headers.Items[0].Height, "reale", headers.Items[len(headers.Items)-1].Height,
			"len", len(headers.Items), "count", count)
		return nil, types.ErrBlockHeightNoMatch
	}
	return headers, nil
}

// 获取当前平行链block对应主链seq，hash信息
// 对于云端主链节点，创世区块记录seq在不同主链节点上差异很大，通过记录的主链hash获取真实seq使用
func (client *client) getLastBlockMainInfo() (int64, *types.Block, error) {
	lastBlock, err := client.getLastBlockInfo()
	if err != nil {
		return -2, nil, err
	}
	//如果在云端节点获取不到对应MainHash，切换到switchLocalHashMatchedBlock 去循环查找
	mainSeq, err := client.GetSeqByHashOnMainChain(lastBlock.MainHash)
	if err != nil {
		return 0, lastBlock, nil
	}
	return mainSeq, lastBlock, nil
}

func (client *client) getLastBlockInfo() (*types.Block, error) {
	lastBlock, err := client.RequestLastBlock()
	if err != nil {
		plog.Error("Parachain getLastBlockInfo fail", "err", err)
		return nil, err
	}

	return lastBlock, nil
}

func (client *client) GetLastHeightOnMainChain() (int64, error) {
	var err error

	var headerHeight int64
	if client.subCfg.GrpcMoudle {
		var header = new(types.Header)
		header, err = client.grpcClient.GetLastHeader(context.Background(), &types.ReqNil{})
		if err == nil {
			headerHeight = header.Height
		}
	} else {
		var rpcHeadr rty.Header
		err = client.jsonClient.Call("GetLastHeader", &types.ReqNil{}, &rpcHeadr)
		if err == nil {
			headerHeight = rpcHeadr.Height
		}
	}

	if err != nil {
		plog.Error("GetLastHeightOnMainChain", "Error", err.Error())
		return -1, err
	}

	return headerHeight, nil
}

func (client *client) GetLastSeqOnMainChain() (int64, error) {
	var seq = new(types.Int64)
	var err error
	if client.subCfg.GrpcMoudle {
		seq, err = client.grpcClient.GetLastBlockSequence(context.Background(), &types.ReqNil{})
	} else {
		var seqi interface{}
		err = client.jsonClient.Call("GetLastBlockSequence", &types.ReqNil{}, &seqi)
		if err == nil {
			seq.Data = int64(seqi.(float64))
		}
	}

	if err != nil {
		plog.Error("GetLastSeqOnMainChain", "Error", err.Error())
		return -1, err
	}
	//the reflect checked in grpcHandle
	return seq.Data, nil
}

func (client *client) GetHashByHeightOnMainChain(height int64) ([]byte, error) {
	var reply = new(types.ReplyHash)
	var err error
	if client.subCfg.GrpcMoudle {
		reply, err = client.grpcClient.GetBlockHash(context.Background(), &types.ReqInt{Height: height})
	} else {
		var blockhash rty.ReplyHash
		err = client.jsonClient.Call("GetBlockHash", &types.ReqInt{Height: height}, &blockhash)
		if err == nil {
			reply.Hash ,_= common.FromHex(blockhash.Hash)
		}

	}
	if err != nil {
		plog.Error("GetHashByHeightOnMainChain", "Error", err.Error())
		return nil, err
	}
	return reply.Hash, nil
}

//GetSeqByHashOnMainChain
func (client *client) GetSeqByHashOnMainChain(hash []byte) (int64, error) {
	var seq = new(types.Int64)
	var err error

	if client.subCfg.GrpcMoudle {
		seq, err = client.grpcClient.GetSequenceByHash(context.Background(), &types.ReqHash{Hash: hash})
	} else {
		err = client.jsonClient.Call("GetSequenceByHash", rty.ReqHashes{Hashes: []string{common.ToHex(hash)}}, seq)
		plog.Info("GetSeqByHashOnMainChain", "seq",seq.Data)
	}

	if err != nil {
		plog.Error("GetSeqByHashOnMainChain", "Error", err.Error(), "hash", hex.EncodeToString(hash))
		return -1, err
	}
	//the reflect checked in grpcHandle
	return seq.Data, nil
}

//GetBlockOnMainBySeq
func (client *client) GetBlockOnMainBySeq(seq int64) (*types.BlockSeq, error) {
	var blockSeq = new(types.BlockSeq)
	var err error
	if client.subCfg.GrpcMoudle {
		blockSeq, err = client.grpcClient.GetBlockBySeq(context.Background(), &types.Int64{Data: seq})
	} else {

		var rblockSeq rty.BlockSeq
		err = client.jsonClient.Call("GetBlockBySeq", types.Int64{Data: seq}, &rblockSeq)
		if err == nil {
			blockSeq.Num = rblockSeq.Num
			var blockDetail types.BlockDetail
			var details rty.BlockDetails
			details.Items = append(details.Items, rblockSeq.Detail)
			err = convertBlockDetails(&details, []*types.BlockDetail{&blockDetail}, false)
			if err == nil {
				blockSeq.Detail = &blockDetail
			}

		}
	}

	if err != nil {
		plog.Error("Not found block on main", "seq", seq)
		return nil, err
	}

	hash := blockSeq.Detail.Block.HashByForkHeight(client.subCfg.MainBlockHashForkHeight)
	if !bytes.Equal(blockSeq.Seq.Hash, hash) {
		plog.Error("para compare ForkBlockHash fail", "forkHeight", client.subCfg.MainBlockHashForkHeight,
			"seqHash", hex.EncodeToString(blockSeq.Seq.Hash), "calcHash", hex.EncodeToString(hash))
		return nil, types.ErrBlockHashNoMatch
	}

	return blockSeq, nil
}

//GetParaTxByTitle
func (client *client) GetParaTxByTitle(req *types.ReqParaTxByTitle) (*types.ParaTxDetails, error) {
	var txDetails = new(types.ParaTxDetails)
	var err error
	if client.subCfg.GrpcMoudle {
		txDetails, err = client.grpcClient.GetParaTxByTitle(context.Background(), req)
	} else {
		var details rty.ParaTxDetails
		err = client.jsonClient.Call("GetParaTxByTitle", *req, &details)
		if err == nil {
			convertParaTxDetails(&details,txDetails)
		}
	}

	if err != nil {
		plog.Error("GetParaTxByTitle wrong", "err", err.Error(), "start", req.Start, "end", req.End, "title", req.Title)
		return nil, err
	}

	return txDetails, nil
}

//QueryTxOnMainByHash
func (client *client) QueryTxOnMainByHash(hash []byte) (*types.TransactionDetail, error) {
	var detail = new(types.TransactionDetail)
	var err error
	if client.subCfg.GrpcMoudle {
		detail, err = client.grpcClient.QueryTransaction(context.Background(), &types.ReqHash{Hash: hash})
	} else {
		var rtx rty.TransactionDetail
		err = client.jsonClient.Call("QueryTransaction", rty.QueryParm{Hash: hex.EncodeToString(hash)}, &rtx)
		if err == nil {
			convertTransactionDetail(&rtx, detail)
		}
	}

	if err != nil {
		plog.Error("QueryTxOnMainByHash Not found", "txhash", common.ToHex(hash))
		return nil, err
	}

	return detail, nil
}

//GetParaHeightsByTitle Yes
func (client *client) GetParaHeightsByTitle(req *types.ReqHeightByTitle) (*types.ReplyHeightByTitle, error) {
	//from blockchain db
	var heights = new(types.ReplyHeightByTitle)
	var err error
	if client.subCfg.GrpcMoudle {
		heights, err = client.grpcClient.LoadParaTxByTitle(context.Background(), req)
	} else {
		var rheights rty.ReplyHeightByTitle
		err = client.jsonClient.Call("LoadParaTxByTitle", *req, &rheights)
		if err == nil {
			heights.Title = rheights.Title
			for _, item := range rheights.Items {
				var info types.BlockInfo
				info.Hash ,_= common.FromHex(item.Hash)
				info.Height = item.Height
				heights.Items = append(heights.Items, &info)
			}

		}
	}

	if err != nil {
		plog.Error("GetParaHeightsByTitle fail", "err", err)
		return nil, err
	}

	return heights, nil
}

//GetParaTxByHeight Yes
func (client *client) GetParaTxByHeight(req *types.ReqParaTxByHeight) (*types.ParaTxDetails, error) {
	//from blockchain db
	var txdetails = new(types.ParaTxDetails)
	var err error
	if client.subCfg.GrpcMoudle {
		txdetails, err = client.grpcClient.GetParaTxByHeight(context.Background(), req)
	} else {
		var rpctxdetails rty.ParaTxDetails
		err = client.jsonClient.Call("GetParaTxByHeight", *req, &rpctxdetails)
		if err == nil {
			convertParaTxDetails(&rpctxdetails, txdetails)
		}
	}

	if err != nil {
		plog.Error("GetParaTxByHeight get node status block count fail")
		return nil, err
	}

	//可以小于等于，不能大于
	if len(txdetails.Items) > len(req.Items) {
		plog.Error("GetParaTxByHeight get blocks more than req")
		return nil, types.ErrInvalidParam
	}
	return txdetails, nil
}

func convertTxdetail(txdetail *rty.TxDetail, retTxdetail *types.TxDetail) {
	var receiptdata types.ReceiptData
	receiptdata.Ty = txdetail.Receipt.Ty
	for _, log := range txdetail.Receipt.Logs {
		var rlog types.ReceiptLog
		rlog.Log,_ = common.FromHex(log.Log)
		rlog.Ty = log.Ty
		receiptdata.Logs = append(receiptdata.Logs, &rlog)
	}

	var tx types.Transaction
	convertTx(txdetail.Tx,&tx)
	retTxdetail.Index = txdetail.Index
	for _, proof := range txdetail.Proofs {
		pbf,_:=common.FromHex(proof)
		retTxdetail.Proofs = append(retTxdetail.Proofs, pbf)
	}
	retTxdetail.Receipt=&receiptdata
	retTxdetail.Tx = &tx

}

func convertHeader(header *rty.Header, retHeader *types.Header) {
	retHeader.Height = header.Height
	retHeader.Hash,_ = common.FromHex(header.Hash)
	retHeader.Version = header.Version
	retHeader.BlockTime = header.BlockTime
	retHeader.TxCount = header.TxCount
	retHeader.Difficulty = header.Difficulty
	retHeader.ParentHash,_ = common.FromHex(header.ParentHash)
	retHeader.StateHash,_ = common.FromHex(header.StateHash)
	retHeader.TxHash,_ = common.FromHex(header.TxHash)
	if header.Signature != nil {
		var sig types.Signature
		sig.Ty = header.Signature.Ty
		sig.Pubkey,_ = common.FromHex(header.Signature.Pubkey)
		sig.Signature,_ = common.FromHex(header.Signature.Signature)
		retHeader.Signature = &sig
	}

}

func convertBlockDetails(details *rty.BlockDetails, retDetails []*types.BlockDetail, isDetail bool) error {

	for _, item := range details.Items {
		var retDetail types.BlockDetail
		var block types.Block
		if item == nil || item.Block == nil {
			retDetails = append(retDetails, nil)
			continue
		}

		block.BlockTime = item.Block.BlockTime
		block.Height = item.Block.Height
		block.Version = item.Block.Version
		block.ParentHash,_ = common.FromHex(item.Block.ParentHash)
		block.StateHash,_ = common.FromHex(item.Block.StateHash)
		block.TxHash,_ = common.FromHex(item.Block.TxHash)
		block.Difficulty=item.Block.Difficulty
		pub,_:=common.FromHex(item.Block.Signature.Pubkey)
		sig,_:=common.FromHex(item.Block.Signature.Signature)

		block.Signature=&types.Signature{Ty:item.Block.Signature.Ty,Pubkey:pub,
			Signature:sig}
		block.MainHeight=item.Block.MainHeight
		block.MainHash,_=common.FromHex(item.Block.MainHash)

		txs := item.Block.Txs
		if isDetail && len(txs) != len(item.Receipts) { //只有获取详情时才需要校验txs和Receipts的数量是否相等CHAIN33-540
			return types.ErrDecode
		}
		for _, tx := range txs {
			var tran types.Transaction
			convertTx(tx,&tran)
			block.Txs = append(block.Txs, &tran)
		}
		retDetail.Block = &block
		for _, rp := range item.Receipts {
			var recp types.ReceiptData
			recp.Ty = rp.Ty
			for _, log := range rp.Logs {
				lg,_:=common.FromHex(log.RawLog)
				recp.Logs = append(recp.Logs,
					&types.ReceiptLog{Ty: log.Ty, Log: lg})
			}

			retDetail.Receipts = append(retDetail.Receipts, &recp)
		}
		retDetails = append(retDetails, &retDetail)
	}

	return nil
}


func convetLog(execer string,rlog *rty.ReceiptDataResult,result *types.ReceiptData){

	result.Ty=rlog.Ty
	for _,l:=range rlog.Logs{
		var logIns []byte
		logType := types.LoadLog([]byte(execer), int64(l.Ty))
		if logType == nil {
			logIns = nil
		} else {
			var info *types.LogInfo
			ety:=types.LoadExecutorType(execer)
			if ety!=nil{
				logMap := ety.GetLogMap()
			logTy,ok:=	logMap[int64(rlog.Ty)]
			if !ok{
				continue
			}
			info=logTy
			}else{
				logty,ok:=	types.SystemLog[int64(rlog.Ty)]
				if ok{
					info=logty
				}else{
					info=types.SystemLog[0]
				}
			}

			pdata := reflect.New(info.Ty)
			 if !pdata.CanInterface() {
				continue
			}
			msg,ok:=pdata.Interface().(proto.Message)
			if !ok{
				continue
			}
			proto.Unmarshal(l.Log,msg)
			logIns=	types.Encode(msg)
		}
		result.Logs=append(result.Logs,&types.ReceiptLog{Ty:l.Ty,Log:logIns})

	}


}

func convertTx(tx *rty.Transaction,reTx  *types.Transaction){
	reTx.Execer=[]byte(tx.Execer)
	reTx.Fee=tx.Fee
	reTx.Expire=tx.Expire
	reTx.Nonce=tx.Nonce
	reTx.GroupCount=tx.GroupCount
	reTx.Header,_=common.FromHex(tx.Header)
	reTx.Next,_=common.FromHex(tx.Next)
	reTx.Payload,_=common.FromHex(tx.RawPayload)
	pub,_:=common.FromHex(tx.Signature.Pubkey)
	sig,_:=common.FromHex(tx.Signature.Signature)
	if tx.Signature != nil {
		reTx.Signature = &types.Signature{Ty: tx.Signature.Ty,
			Pubkey:    pub,
			Signature: sig}
	}
	exec := types.LoadExecutorType(tx.Execer)
	if exec==nil{
		reTx.To=tx.To
	}else{
		reTx.To=address.ExecAddress(tx.Execer)
	}

}

func convertTransactionDetail(detail *rty.TransactionDetail, redetail *types.TransactionDetail) {
	var assets []*types.Asset
	for _, a := range detail.Assets {
		assert := &types.Asset{
			Exec:   a.Exec,
			Symbol: a.Symbol,
			Amount: a.Amount,
		}
		assets = append(assets, assert)
	}
	var proofs [][]byte
	for _, proof := range detail.Proofs {
		pf,_:=common.FromHex(proof)
		proofs = append(proofs, pf)
	}
	var receipt types.ReceiptData
	//convert ReceiptDataResult to ReceiptData
	convetLog(detail.Tx.Execer,detail.Receipt,&receipt)


	var txproofs []*types.TxProof
	for _, txproof := range detail.TxProofs {
		var tyTxproof types.TxProof
		tyTxproof.Index = txproof.Index
		tyTxproof.RootHash ,_= common.FromHex(txproof.RootHash)
		for _, proof := range txproof.Proofs {
			pf,_:=common.FromHex(proof)
			tyTxproof.Proofs = append(tyTxproof.Proofs, pf)
		}

		txproofs = append(txproofs, &tyTxproof)

	}

	var tran types.Transaction
	convertTx(detail.Tx,&tran)
	redetail.Tx = &tran
	redetail.Height = detail.Height
	redetail.Index = detail.Index
	redetail.Blocktime = detail.Blocktime
	redetail.Receipt = &receipt
	redetail.Proofs = proofs
	redetail.Amount = detail.Amount
	redetail.Fromaddr = detail.Fromaddr
	redetail.ActionName = detail.ActionName
	redetail.Assets = assets
	redetail.TxProofs = txproofs
	redetail.FullHash,_ = common.FromHex(detail.FullHash)

}

func convertParaTxDetails(ptxdetails *rty.ParaTxDetails, message *types.ParaTxDetails) {
	for _, item := range ptxdetails.Items {
		var ptxdetail types.ParaTxDetail
		var header types.Header
		ptxdetail.Index = item.Index
		ptxdetail.ChildHash ,_= common.FromHex(item.ChildHash)
		ptxdetail.Type = item.Type
		for _, proof := range item.Proofs {
			pf,_:=common.FromHex(proof)
			ptxdetail.Proofs = append(ptxdetail.Proofs, pf)
		}

		for _, txdetail := range item.TxDetails {
			var detail types.TxDetail
			convertTxdetail(txdetail, &detail)
			ptxdetail.TxDetails = append(ptxdetail.TxDetails, &detail)
		}

		convertHeader(item.Header,&header)
		ptxdetail.Header = &header
		message.Items = append(message.Items, &ptxdetail)
	}

	return

}
