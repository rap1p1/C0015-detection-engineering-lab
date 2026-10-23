/*
   C0015 — Go-compiled Cobalt Strike beacon DLL
   Reference: https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/

   The two beacon DLLs in the campaign are Go builds with no version metadata and a revoked or
   absent signature. The strings below are Go runtime artefacts that survive symbol stripping.
   The size ceiling separates a beacon-sized module from a full Go application.
*/

rule C0015_GoBeacon_DLL
{
    meta:
        description = "Go-compiled beacon DLL with no version metadata"
        author = "rap1p1"
        date = "2026-10-23"
        reference = "https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/"
        hash1 = "4a49cf7539f9fd5cc066dc493bf16598a38a75f7b656224db1ddd33005ad76f6"
        hash2 = "6f844a6e903aa8e305e88ac0f60328c184f71a4bfbe93124981d6a4308b14610"

    strings:
        $go1 = "Go build ID:" ascii
        $go2 = "runtime: gp: gp=" ascii
        $go3 = "runtime: bad pointer in frame" ascii
        $go4 = "write barrier" ascii
        $go5 = "GODEBUG: can not enable" ascii
        $go6 = "reflect: call of reflect.Value" ascii
        $import1 = "GetQueuedCompletionStatus" ascii wide
        $import2 = "CryptAcquireContextW" ascii wide
        $import3 = "CertOpenSystemStoreW" ascii wide
        $import4 = "WinHttpOpen" ascii wide
        $import5 = "RtlCreateUserThread" ascii wide

    condition:
        uint16(0) == 0x5a4d
        and filesize < 4MB
        and 3 of ($go*)
        and 2 of ($import*)
}
