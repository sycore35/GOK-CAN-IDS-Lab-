"""Tests for ISO-TP Multi-Frame Reassembly and UDS Diagnostic Security Auditing."""

import pytest
from src.can_frame import CANFrame
from src.isotp_uds import ISOTPReassembler, UDSServiceAuditor


def test_isotp_single_frame():
    # SF containing UDS ReadDataByIdentifier (0x22 0xF1 0x90 - VIN read)
    # PCI: 0x03 (SF len 3), payload: 0x22 0xF1 0x90
    frame = CANFrame(arbitration_id=0x7E0, data=bytes([0x03, 0x22, 0xF1, 0x90, 0x00, 0x00, 0x00, 0x00]))
    reassembler = ISOTPReassembler()
    res = reassembler.process_frame(frame)
    
    assert res["status"] == "COMPLETE"
    assert res["payload"] == bytes([0x22, 0xF1, 0x90])
    
    msg = UDSServiceAuditor.audit_uds_payload(res["arbitration_id"], res["payload"])
    assert msg.service_name == "ReadDataByIdentifier"
    assert msg.security_risk == "LOW"


def test_isotp_multi_frame_reassembly():
    # First Frame: Total Length = 15 bytes. PCI: 0x10 0x0F, payload chunk: 6 bytes
    ff = CANFrame(arbitration_id=0x7E0, data=bytes([0x10, 0x0F, 0x34, 0x00, 0x44, 0x00, 0x10, 0x00]))
    # Consecutive Frame 1: SN=1, 7 bytes payload
    cf1 = CANFrame(arbitration_id=0x7E0, data=bytes([0x21, 0x00, 0x00, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC]))
    # Consecutive Frame 2: SN=2, 2 bytes payload to reach total 15 bytes
    cf2 = CANFrame(arbitration_id=0x7E0, data=bytes([0x22, 0xDD, 0xEE, 0x00, 0x00, 0x00, 0x00, 0x00]))
    
    reassembler = ISOTPReassembler()
    r1 = reassembler.process_frame(ff)
    assert r1["status"] == "IN_PROGRESS"
    assert r1["accumulated"] == 6
    
    r2 = reassembler.process_frame(cf1)
    assert r2["status"] == "IN_PROGRESS"
    assert r2["accumulated"] == 13
    
    r3 = reassembler.process_frame(cf2)
    assert r3["status"] == "COMPLETE"
    assert len(r3["payload"]) == 15
    assert r3["payload"][0] == 0x34  # RequestDownload
    
    msg = UDSServiceAuditor.audit_uds_payload(r3["arbitration_id"], r3["payload"])
    assert msg.service_name == "RequestDownload"
    assert msg.security_risk == "CRITICAL"


def test_isotp_sequence_discontinuity_detection():
    # FF expecting SN=1 next
    ff = CANFrame(arbitration_id=0x7E0, data=bytes([0x10, 0x14, 0x2E, 0xF1, 0x90, 0x01, 0x02, 0x03]))
    # CF with invalid SN=3 (instead of 1)
    cf_bad = CANFrame(arbitration_id=0x7E0, data=bytes([0x23, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]))
    
    reassembler = ISOTPReassembler()
    reassembler.process_frame(ff)
    res = reassembler.process_frame(cf_bad)
    
    assert res["status"] == "ERROR"
    assert res["error"] == "SEQUENCE_MISMATCH"
    assert res["expected"] == 1
    assert res["got"] == 3


def test_orphan_consecutive_frame():
    # CF without prior FF
    cf_orphan = CANFrame(arbitration_id=0x7E0, data=bytes([0x21, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]))
    reassembler = ISOTPReassembler()
    res = reassembler.process_frame(cf_orphan)
    assert res["status"] == "ERROR"
    assert res["error"] == "ORPHAN_CONSECUTIVE_FRAME"
