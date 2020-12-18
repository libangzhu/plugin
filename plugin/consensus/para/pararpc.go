// Copyright Fuzamei Corp. 2018 All Rights Reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package para

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/33cn/chain33/common"
	rty "github.com/33cn/chain33/rpc/types"
	"github.com/33cn/chain33/types"
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
			for index, rheader := range rheader.Items {
				var header types.Header
				convertHeader(rheader, &header)
				headers.Items[index] = &header
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
		err = client.jsonClient.Call("GetLastBlockSequence", &types.ReqNil{}, seq)
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
			reply.Hash = common.HexToHash(blockhash.Hash).Bytes()
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
		err = client.jsonClient.Call("GetSequenceByHash", types.ReqHash{Hash: hash}, seq)
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
		var rblockseq rty.BlockSeq
		err = client.jsonClient.Call("GetBlockBySeq", &types.Int64{Data: seq}, &rblockseq)
		if err == nil {
			blockSeq.Num = rblockseq.Num
			var blockdetail types.BlockDetail
			var details rty.BlockDetails
			details.Items = append(details.Items, rblockseq.Detail)
			err = convertBlockDetails(&details, []*types.BlockDetail{&blockdetail}, false)
			if err == nil {
				blockSeq.Detail = &blockdetail
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
		err = client.jsonClient.Call("GetParaTxByTitle", req, &details)
		if err == nil {
			for index, item := range details.Items {
				var pdetail types.ParaTxDetail
				pdetail.Type = item.Type
				pdetail.ChildHash = common.HexToHash(item.ChildHash).Bytes()
				pdetail.Index = item.Index
				for _, proof := range item.Proofs {
					pdetail.Proofs = append(pdetail.Proofs, common.HexToHash(proof).Bytes())
				}
				var header types.Header
				convertHeader(item.Header, &header)
				pdetail.Header = &header
				for _, txdetail := range item.TxDetails {
					var detail types.TxDetail
					convertTxdetail(txdetail, &detail)
					pdetail.TxDetails = append(pdetail.TxDetails, &detail)
				}

				txDetails.Items[index] = &pdetail
			}
		}
	}

	if err != nil {
		plog.Error("GetParaTxByTitle wrong", "err", err.Error(), "start", req.Start, "end", req.End)
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
		err = client.jsonClient.Call("QueryTransaction", &rty.QueryParm{Hash: hex.EncodeToString(hash)}, &rtx)
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

//GetParaHeightsByTitle
func (client *client) GetParaHeightsByTitle(req *types.ReqHeightByTitle) (*types.ReplyHeightByTitle, error) {
	//from blockchain db
	var heights = new(types.ReplyHeightByTitle)
	var err error
	if client.subCfg.GrpcMoudle {
		heights, err = client.grpcClient.LoadParaTxByTitle(context.Background(), req)
	} else {
		var rheights rty.ReplyHeightByTitle
		err = client.jsonClient.Call("LoadParaTxByTitle", req, &rheights)
		if err == nil {
			heights.Title = rheights.Title
			for _, item := range rheights.Items {
				var info types.BlockInfo
				info.Hash = common.HexToHash(item.Hash).Bytes()
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

//GetParaTxByHeight
func (client *client) GetParaTxByHeight(req *types.ReqParaTxByHeight) (*types.ParaTxDetails, error) {
	//from blockchain db
	var blocks = new(types.ParaTxDetails)
	var err error
	if client.subCfg.GrpcMoudle {
		blocks, err = client.grpcClient.GetParaTxByHeight(context.Background(), req)
	} else {
		var rpcBlocks rty.ParaTxDetails
		err = client.jsonClient.Call("GetParaTxByHeight", req, &rpcBlocks)
		if err == nil {
			for index, item := range rpcBlocks.Items {
				var ptxdetail types.ParaTxDetail
				ptxdetail.Index = item.Index
				ptxdetail.ChildHash = common.HexToHash(item.ChildHash).Bytes()
				ptxdetail.Type = item.Type
				for _, proof := range item.Proofs {
					ptxdetail.Proofs = append(ptxdetail.Proofs, common.HexToHash(proof).Bytes())
				}

				for _, txdetail := range item.TxDetails {
					var detail types.TxDetail
					convertTxdetail(txdetail, &detail)
					ptxdetail.TxDetails = append(ptxdetail.TxDetails, &detail)
				}

				blocks.Items[index] = &ptxdetail
			}

		}
	}

	if err != nil {
		plog.Error("GetParaTxByHeight get node status block count fail")
		return nil, err
	}

	//可以小于等于，不能大于
	if len(blocks.Items) > len(req.Items) {
		plog.Error("GetParaTxByHeight get blocks more than req")
		return nil, types.ErrInvalidParam
	}
	return blocks, nil
}

func convertTxdetail(txdetail *rty.TxDetail, retTxdetail *types.TxDetail) {

	retTxdetail.Index = txdetail.Index
	for _, proof := range txdetail.Proofs {
		retTxdetail.Proofs = append(retTxdetail.Proofs, common.HexToHash(proof).Bytes())
	}
	var receiptdata types.ReceiptData
	receiptdata.Ty = txdetail.Receipt.Ty
	for _, log := range txdetail.Receipt.Logs {
		receiptdata.Logs = append(receiptdata.Logs, common.HexToHash(log).Bytes())
	}
	var tx types.Transaction
	tx.Payload = common.HexToHash(txdetail.Tx.RawPayload).Bytes()
	tx.Expire = txdetail.Tx.Expire
	tx.Next = common.HexToHash(txdetail.Tx.Next).Bytes()
	tx.To = txdetail.Tx.To
	tx.Nonce = txdetail.Tx.Nonce
	tx.GroupCount = txdetail.Tx.GroupCount
	tx.Header = common.HexToHash(txdetail.Tx.Header).Bytes()
	tx.Signature = &types.Signature{Signature: common.HexToHash(txdetail.Tx.Signature.Signature).Bytes(),
		Pubkey: common.HexToHash(txdetail.Tx.Signature.Pubkey).Bytes(), Ty: txdetail.Tx.Signature.Ty}

	retTxdetail.Tx = &tx

}

func convertHeader(header *rty.Header, retHeader *types.Header) {
	retHeader.Height = header.Height
	retHeader.Hash = common.HexToHash(header.Hash).Bytes()
	retHeader.Version = header.Version
	retHeader.BlockTime = header.BlockTime
	retHeader.TxCount = header.TxCount
	retHeader.Difficulty = header.Difficulty
	retHeader.ParentHash = common.HexToHash(header.ParentHash).Bytes()
	retHeader.StateHash = common.HexToHash(header.StateHash).Bytes()
	retHeader.TxHash = common.HexToHash(header.TxHash).Bytes()
	retHeader.Signature.Ty = header.Signature.Ty
	retHeader.Signature.Pubkey = common.HexToHash(header.Signature.Pubkey).Bytes()
	retHeader.Signature.Signature = common.HexToHash(header.Signature.Signature).Bytes()

}

func convertBlockDetails(details *rty.BlockDetails, retDetails []*types.BlockDetail, isDetail bool) error {
	var retDetail types.BlockDetail
	for _, item := range details.Items {
		var block types.Block
		if item == nil || item.Block == nil {
			retDetails = append(retDetails, nil)
			continue
		}

		block.BlockTime = item.Block.BlockTime
		block.Height = item.Block.Height
		block.Version = item.Block.Version
		block.ParentHash = common.HexToHash(item.Block.ParentHash).Bytes()
		block.StateHash = common.HexToHash(item.Block.StateHash).Bytes()
		block.TxHash = common.HexToHash(item.Block.TxHash).Bytes()
		txs := item.Block.Txs
		if isDetail && len(txs) != len(item.Receipts) { //只有获取详情时才需要校验txs和Receipts的数量是否相等CHAIN33-540
			return types.ErrDecode
		}
		for _, tx := range txs {
			var tran = &types.Transaction{
				Execer:     []byte(tx.Execer),
				Fee:        tx.Fee,
				Expire:     tx.Expire,
				Header:     common.HexToHash(tx.Header).Bytes(),
				Next:       common.HexToHash(tx.Next).Bytes(),
				To:         tx.To,
				Nonce:      tx.Nonce,
				GroupCount: tx.GroupCount,
				Signature: &types.Signature{Ty: tx.Signature.Ty,
					Pubkey:    common.HexToHash(tx.Signature.Pubkey).Bytes(),
					Signature: common.HexToHash(tx.Signature.Signature).Bytes()},
				Payload: common.HexToHash(tx.RawPayload).Bytes(),
			}

			block.Txs = append(block.Txs, tran)
		}
		retDetail.Block = &block

		for i, rp := range item.Receipts {
			var recp types.ReceiptData
			recp.Ty = rp.Ty
			for _, log := range rp.Logs {
				recp.Logs = append(recp.Logs,
					&types.ReceiptLog{Ty: log.Ty, Log: common.HexToHash(log.RawLog).Bytes()})
			}

			retDetail.Receipts = append(retDetail.Receipts, &recp)
		}
		retDetails = append(retDetails, &retDetail)
	}
	return nil
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
		proofs = append(proofs, common.HexToHash(proof).Bytes())
	}
	var receipt types.ReceiptData
	receipt.Ty = detail.Receipt.Ty
	for _, log := range detail.Receipt.Logs {
		receipt.Logs = append(receipt.Logs, &types.ReceiptLog{Ty: log.Ty, Log: common.HexToHash(log.RawLog).Bytes()})
	}

	var txproofs []*types.TxProof
	for _, txproof := range detail.TxProofs {
		var tyTxproof types.TxProof
		tyTxproof.Index = txproof.Index
		tyTxproof.RootHash = common.HexToHash(txproof.RootHash).Bytes()
		for _, proof := range txproof.Proofs {
			tyTxproof.Proofs = append(tyTxproof.Proofs, common.HexToHash(proof).Bytes())
		}

		txproofs = append(txproofs, &tyTxproof)

	}

	var tran = &types.Transaction{
		Execer:     []byte(detail.Tx.Execer),
		Fee:        detail.Tx.Fee,
		Expire:     detail.Tx.Expire,
		Header:     common.HexToHash(detail.Tx.Header).Bytes(),
		Next:       common.HexToHash(detail.Tx.Next).Bytes(),
		To:         detail.Tx.To,
		Nonce:      detail.Tx.Nonce,
		GroupCount: detail.Tx.GroupCount,
		Signature: &types.Signature{Ty: detail.Tx.Signature.Ty,
			Pubkey:    common.HexToHash(detail.Tx.Signature.Pubkey).Bytes(),
			Signature: common.HexToHash(detail.Tx.Signature.Signature).Bytes()},
		Payload: common.HexToHash(detail.Tx.RawPayload).Bytes(),
	}

	redetail.Tx = tran
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
	redetail.FullHash = common.HexToHash(detail.FullHash).Bytes()

}
