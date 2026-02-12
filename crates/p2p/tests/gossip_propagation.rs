use scam_core::{
    Block, BlockHeader, OutPoint, Target, Transaction, TxIn, TxOut, hash::hash256, merkle,
};
use scam_p2p::{GossipEngine, InventoryItem, OutboundMessage, WireMessage};

fn sample_tx(seed: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: hash256(&[seed]),
                vout: 0,
            },
            signature: vec![seed; 64],
            pubkey_compressed: vec![2u8; 33],
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: 1,
            key_hash20: [seed; 20],
        }],
        lock_time: 0,
    }
}

fn sample_block(seed: u8) -> Block {
    let tx = sample_tx(seed);
    let txids = vec![tx.txid()];
    Block {
        header: BlockHeader {
            version: 1,
            prev_block: hash256(&[seed.wrapping_add(1)]),
            merkle_root: merkle::merkle_root(&txids),
            timestamp: 1_770_763_200 + seed as u64,
            target: Target::MAX,
            nonce: seed as u64,
        },
        transactions: vec![tx],
    }
}

fn assert_inv_to_peer(messages: &[OutboundMessage], peer: u64, item: InventoryItem) {
    let matched = messages.iter().any(|outbound| {
        outbound.peer_id == peer
            && matches!(
                &outbound.message,
                WireMessage::Inv { items }
                if items.len() == 1 && items[0] == item
            )
    });
    assert!(matched, "missing inv {item:?} for peer {peer}");
}

#[test]
fn tx_propagates_over_inv_getdata_and_is_deduped() {
    let mut engine = GossipEngine::new(256).expect("engine");
    engine.connect_peer(1);
    engine.connect_peer(2);
    engine.connect_peer(3);

    let tx = sample_tx(7);
    let txid = tx.txid();

    let fanout = engine
        .on_message(1, WireMessage::Tx { tx: tx.clone() })
        .expect("tx fanout");
    assert_eq!(fanout.len(), 2);
    assert_inv_to_peer(&fanout, 2, InventoryItem::Tx(txid));
    assert_inv_to_peer(&fanout, 3, InventoryItem::Tx(txid));

    let requested = engine
        .on_message(
            2,
            WireMessage::GetData {
                items: vec![InventoryItem::Tx(txid)],
            },
        )
        .expect("getdata");
    assert_eq!(
        requested,
        vec![OutboundMessage {
            peer_id: 2,
            message: WireMessage::Tx { tx: tx.clone() },
        }]
    );

    let duplicate = engine
        .on_message(2, WireMessage::Tx { tx })
        .expect("duplicate tx message");
    assert!(duplicate.is_empty(), "duplicate tx should not re-fanout");
}

#[test]
fn block_propagates_over_inv_getdata_and_is_deduped() {
    let mut engine = GossipEngine::new(256).expect("engine");
    engine.connect_peer(1);
    engine.connect_peer(2);
    engine.connect_peer(3);

    let block = sample_block(9);
    let block_hash = block.header.block_hash();

    let fanout = engine
        .on_message(
            1,
            WireMessage::Block {
                block: block.clone(),
            },
        )
        .expect("block fanout");
    assert_eq!(fanout.len(), 2);
    assert_inv_to_peer(&fanout, 2, InventoryItem::Block(block_hash));
    assert_inv_to_peer(&fanout, 3, InventoryItem::Block(block_hash));

    let requested = engine
        .on_message(
            3,
            WireMessage::GetData {
                items: vec![InventoryItem::Block(block_hash)],
            },
        )
        .expect("getdata");
    assert_eq!(
        requested,
        vec![OutboundMessage {
            peer_id: 3,
            message: WireMessage::Block {
                block: block.clone(),
            },
        }]
    );

    let duplicate = engine
        .on_message(3, WireMessage::Block { block })
        .expect("duplicate block message");
    assert!(duplicate.is_empty(), "duplicate block should not re-fanout");
}
