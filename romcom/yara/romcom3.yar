import "pe"
import "math"

// ROMCOM 3.0

rule romcom3_stealer {
    meta:
        description = "STEALDEAL"
        author = "Fernando Mercês @ Trend Micro FTR"
        created = "2023-04-04"
        version = 1
        sha256 = "8d805014ceb45195be5bab07a323970a1aa8bc60cdc529712bccaf6f3103e6a6"
    strings:
        $stealDll = "stealDll.dll"
    condition:
        pe.machine == pe.MACHINE_AMD64
        and pe.is_dll()
        and pe.number_of_exports == 1
        and pe.export_details[0].name matches /^stub$/
        and $stealDll
}

rule romcom3_exe_dropper {
    meta:
        description = "ROMCOM EXE dropper"
        author = "Fernando Mercês @ Trend Micro FTR"
        created = "2023-04-04"
        version = 2
        sha256 = "6d3ab9e729bb03ae8ae3fcd824474c5052a165de6cb4c27334969a542c7b261d"
    strings:
        $rdata = "@_RDATA"
        $main = ".dll\x00Main"
    condition:
        pe.machine == pe.MACHINE_AMD64
        and not pe.is_dll()
        and $main
        and #rdata > 2
        and for 2 i in pe.resources : (
            i.type_string == "B\x00I\x00N\x00A\x00R\x00Y\x00"
            and uint16be(i.offset) == 0x4d5a
        )
}

rule romcom3_dll_dropper {
    meta:
        description = "ROMCOM dropper"
        author = "Fernando Mercês @ Trend Micro FTR"
        created = "2023-04-04"
        version = 1
        sha256 = "3e7bf3a34c4dfa6abfce8254f213cbc98331504fa956b8d35e0961966593034f"
        sha256 = "ca0ccf331b2545102452e3b505a64444f50ab00d406564dda6ea5987f0194208"
        sha256 = "3b26e27031a00a32f3616de5179a003951a9c92381cd8ec552d39f7285ff42ee"
    condition:
        pe.DLL
        and pe.machine == pe.MACHINE_AMD64
        and pe.number_of_sections <= 10
        and pe.number_of_exports == 1
        and pe.export_details[0].name matches /^Main$/
        and for all i in pe.resources : (
            i.type_string == "B\x00I\x00N\x00A\x00R\x00Y\x00"
            and uint16be(i.offset) == 0x4d5a
        )
}

rule romcom3_component_protected {
    meta:
        description = "ROMCOM DLL component (worker/network) protected by VMProtect"
        author = "Fernando Mercês @ Trend Micro FTR"
        created = "2023-04-04"
        version = 2
        sha256 = "597dd1e09bd23cd18132ce27a731d0b66c78381e90292ece0f23738773743a7c"
        sha256 = "7424de0984159e0c01da89a429e036835f253de35ec2bdade0b91db906ec54ec"
        sha256 = "96d1cd0a6038ee295b02f038a30ac756bae0ee5ae26f5a64637adf86777d7e14"
    condition:
        pe.DLL
        and pe.machine == pe.MACHINE_AMD64
        and (pe.number_of_sections == 7 or pe.number_of_sections == 9)
        and pe.number_of_exports == 1
        and pe.export_details[0].name matches /^Main$/
        and pe.number_of_resources == 0
        and for 2 s in pe.sections : (
            math.entropy(s.raw_data_offset, s.raw_data_size) > 7
        )
}

rule romcom3_component_unprotected {
    meta:
        description = "ROMCOM DLL component (worker/network)"
        author = "Fernando Mercês @ Trend Micro FTR"
        created = "2023-05-16"
        version = 1
    condition:
        pe.DLL
        and pe.machine == pe.MACHINE_AMD64
        and pe.number_of_exports == 1
        and pe.export_details[0].name matches /^Main$/
        and pe.number_of_resources == 0
        and (
            pe.imphash() == "e505937470c5553c9280302686ce4f26"
            or pe.imphash() == "55fa054cb4633efda89c942ce5be30ee"
            or pe.imphash() == "55be9467bec03197155115e801a15149"
        )
}

rule romcom3_loader {
    meta:
        description = "ROMCOM loader with forward exports"
        author = "Fernando Mercês @ Trend Micro FTR"
        created = "2023-04-04"
        version = 2
        sha256 = "dd65c3ad7473f211ae661ccc37f8017b9697dfffb75d415cb035399c14bc1bc9"
        sha256 = "ad39ad35084d8339744299def3af979e666add8103ebd706de3cd1430d3ca8a1"
        sha256 = "e58fcd4a8d13cb1847f08fd3db6f86473c589f935bcf76ff2837bfac3e8f8f6e"
        sha256 = "916153d8265a2f9344648e302c6b7b8d7e1f40f704b0df83edde43986ab68e56"
        sha256 = "555ef671179b83989858b6d084b3aee0a379c9d8c75ca292961373d3b71315f8"
    condition:
        pe.DLL
        and pe.machine == pe.MACHINE_AMD64
        and (pe.number_of_sections >= 5 and pe.number_of_sections <= 10)
        and pe.number_of_resources == 0
        and for all e in pe.export_details : (
            e.forward_name
        )
        and for 2 i in pe.export_details: (
            i.forward_name matches /\.Dll(CanUnloadNow|GetClassObject)$/
        )
}