"""Adversarial C07 original PDF-source checks. Run with pytest in broker."""
from c07_a10_c10_original_evidence import _pdf


def make_pdf(crossref=b"xref\n0 1\n0000000000 65535 f \n"):
    head = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    offset = len(head)
    return head + crossref + b"trailer\n<< /Size 1 >>\nstartxref\n" + str(offset).encode() + b"\n%%EOF\n"


def test_accept_structurally_plausible_xref_table():
    assert _pdf(make_pdf())


def test_reject_header_eof_only_forgery():
    assert not _pdf(b"%PDF-1.7\n" + b"filler" * 30 + b"\n%%EOF\n")


def test_reject_out_of_range_xref_pointer():
    assert not _pdf(b"%PDF-1.7\nstartxref\n99999\n%%EOF\n")


def test_reject_nonxref_pointer():
    assert not _pdf(make_pdf(crossref=b"not_a_cross_reference\n"))


def test_reject_trailing_payload_after_eof():
    assert not _pdf(make_pdf() + b"unsafe trailing data")


def test_reject_non_pdf_header():
    assert not _pdf(make_pdf().replace(b"%PDF-1.7", b"%PDF-9.9", 1))


def test_reject_wrong_type():
    assert not _pdf("%PDF-1.7\n%%EOF")
