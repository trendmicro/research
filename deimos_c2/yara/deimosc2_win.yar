import "pe"

/* 
 * Description: Ruleset for detecting Deimos C2 Windows agents
 * Author: Fernando Mercês @ Trend Micro FTR
 * 
 * Last updated: 2022-08-05
*/

global private rule deimos_pe {
    condition:
        pe.number_of_sections == 5
        and pe.sections[4].name == ".symtab"
        and filesize >= 6400000 and filesize <= 7700000
}

// 64-bit files

rule deimosc2_agent_win64_https {
    meta:
        description = "Non-obfuscated PE32+ Deimos C2 Agents using HTTPS via http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $deimos = "github.com/DeimosC2/DeimosC2/agents/resources"
        $net_Dial = {65488B0C2528000000488B8900000000488D4424C0483B41100F86D40000004881ECC00000004889AC24B8000000488DAC24B8000000488D7C24580F57C0488D7FE048896C24F0488D6C24F0}
        $http_Post = {65488B0C2528000000488B8900000000488D4424F8483B41100F86FE0100004881EC880000004889AC2480000000488DAC2480000000488B053B884A00488D0D7C24220048890C244889442408488D057BCF1800488944241048C744241804000000488B8424980000004889442420488B8424A00000004889442428488B8424B80000004889442430488B8424C00000004889442438}

    condition:
        #deimos > 10
        and all of them
}

rule deimosc2_agent_win64_tcp {
    meta:
        description = "Non-obfuscated PE32+ Deimos C2 Agents using TCP via net.Dial() should not have http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $deimos = "github.com/DeimosC2/DeimosC2/agents/resources"
        $net_Dial = {65488B0C2528000000488B8900000000488D4424C0483B41100F86D40000004881ECC00000004889AC24B8000000488DAC24B8000000488D7C24580F57C0488D7FE048896C24F0488D6C24F0}
        $http_Post = {65488B0C2528000000488B8900000000488D4424F8483B41100F86FE0100004881EC880000004889AC2480000000488DAC2480000000488B053B884A00488D0D7C24220048890C244889442408488D057BCF1800488944241048C744241804000000488B8424980000004889442420488B8424A00000004889442428488B8424B80000004889442430488B8424C00000004889442438}

    condition:
        #deimos > 10
        and $net_Dial
        and not $http_Post
}

private rule deimosc2_agent_win64_colon_decrypt_obfuscated {
    meta:
        description = "Detects gobfuscate XOR decryption 64-bit routine for a single colon character"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $colon = {
            65 48 8B 0C 25 28 00 00 00    // mov     rcx, gs:28h
            48 8B 89 00 00 00 00          // mov     rcx, [rcx+0]
            48 3B 61 10                   // cmp     rsp, [rcx+10h]
            0F 86 81 00 00 00             // jbe     loc_760B5B            
            48 83 EC 40                   // sub     rsp, 40h
            48 89 6C 24 38                // mov     [rsp+40h+var_9+1], rbp
            48 8D 6C 24 38                // lea     rbp, [rsp+40h+var_9+1]
            C6 44 24 36 ??                // mov     [rsp+40h+var_A], 0Bh
            C6 44 24 35 ??                // mov     [rsp+40h+var_B], 31h ; '1'
            C6 44 24 37 00                // mov     byte ptr [rsp+40h+var_9], 0
            31 C0                         // xor     eax, eax
            EB 13
        }
    condition:
        pe.is_64bit()
        and for 1 i in (1..#colon) : (
                uint8(@colon[i] + 44) ^ uint8(@colon[i] + 49) == 0x3a // ':'
            )
}

rule deimosc2_agent_win64_https_obfuscated {
    meta:
        description = "Detects the code piece that checks for a 200 OK return from http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-07-26"
    
    strings:
        $http_ok_check = {
            48 8B 48 40                   // mov     rcx, [rax+40h]
            84 01                         // test    [rcx], al
            48 83 C1 18                   // add     rcx, 18h
            48 8B 58 48                   // mov     rbx, [rax+48h]
            48 89 8C 24 60 01 00 00       // mov     qword ptr [rsp+170h+var_18+8], rcx
            48 89 9C 24 58 01 00 00       // mov     qword ptr [rsp+170h+var_18], rbx
            C6 44 24 6F 01                // mov     [rsp+170h+var_101], 1
            48 81 78 10 C8 00 00 00       // cmp     qword ptr [rax+10h], 0C8h
            0F 85 43 01 00 00
        }

    condition:
        deimosc2_agent_win64_colon_decrypt_obfuscated
        and all of them
}

rule deimosc2_agent_win64_tcp_obfuscated {
    meta:
        description = "Detects the net.Dial() code"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $net_dial = {
            48 8B 44 24 40                // mov     rax, [rsp+0C8h+var_90.len]
            48 8B 4C 24 38                // mov     rcx, [rsp+0C8h+var_90.ptr]
            48 8B 94 24 B0 00 00 00       // mov     rdx, [rsp+0C8h+var_18.ptr]
            48 89 14 24                   // mov     [rsp+0C8h+var_C8.ptr], rdx ; string
            48 8B 54 24 78                // mov     rdx, [rsp+0C8h+var_50]
            48 89 54 24 08                // mov     [rsp+0C8h+var_C8.len], rdx
            48 89 4C 24 10                // mov     [rsp+0C8h+var_B8.ptr], rcx ; string
            48 89 44 24 18                // mov     [rsp+0C8h+var_B8.len], rax
            E8 93 92 DF FF           
        }
        $http_Post  = {65488B0C2528000000488B8900000000488D4424F8483B41100F86FE0100004881EC880000004889AC2480000000488DAC2480000000488B053B884A00488D0D7C24220048890C244889442408488D057BCF1800488944241048C744241804000000488B8424980000004889442420488B8424A00000004889442428488B8424B80000004889442430488B8424C00000004889442438}

    condition:
        deimosc2_agent_win64_colon_decrypt_obfuscated
        and all of them
        and not $http_Post
}

// 32-bit files

rule deimosc2_agent_win32_https {
    meta:
        description = "Non-obfuscated PE32 Deimos C2 Agents using HTTPS via http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $deimos = "github.com/DeimosC2/DeimosC2/agents/resources"
        $net_Dial = {E8??0000008B4C24248B5424208B5C241C8B6C2428899C248400000089942488000000898C248C00000089AC249000000083C470C3}
        $http_Post = {
            E8 ?? ?? ?? 00               //                 call    net_http_NewRequestWithContext
            8B 44 24 20                  //                 mov     eax, [esp+40h+var_20]
            8B 4C 24 24                  //                 mov     ecx, [esp+40h+var_1C]
            8B 54 24 28                  //                 mov     edx, [esp+40h+var_18]
            85 C9                        //                 test    ecx, ecx
            0F 85 F4 00 00 00            //                 jnz     loc_6203AB
            89 44 24 30                  //                 mov     [esp+40h+var_10], eax
            8B 48 1C                     //                 mov     ecx, [eax+1Ch]
            89 4C 24 3C                  //                 mov     [esp+40h+var_4], ecx
            90                           //                 nop
            8D 15 ?? ?? ?? 00            //                 lea     edx, aContentType ; "Content-Type"
            89 14 24                     //                 mov     [esp+40h+var_40], edx ; int
            C7 44 24 04 0C 00 00 00      //                 mov     [esp+40h+var_3C], 0Ch ; int
            E8 ?? ?? ?? FF               //                 call    net_textproto_CanonicalMIMEHeaderKey
        }

    condition:
        #deimos > 10
        and all of them
}

rule deimosc2_agent_win32_tcp {
    meta:
        description = "Non-obfuscated PE32 Deimos C2 Agents using TCP via net.Dial()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $deimos = "github.com/DeimosC2/DeimosC2/agents/resources"
        $net_Dial = {E8??0000008B4C24248B5424208B5C241C8B6C2428899C248400000089942488000000898C248C00000089AC249000000083C470C3}
        $http_Post = {E86AEBFFFF8B4424108B4C240C8B54240889542460894C24648944246883C440C3}

    condition:
        #deimos > 10
        and $net_Dial
        and not $http_Post
}

private rule deimosc2_agent_win32_colon_decrypt_obfuscated {
    meta:
        description = "Detects gobfuscate XOR decryption 32-bit routine for a single colon character"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $colon = {
            64 8B 0D 14 00 00 00        // mov     ecx, large fs:14h
            8B 89 00 00 00 00           // mov     ecx, [ecx+0]
            3B 61 08                    // cmp     esp, [ecx+8]
            76 73                       // jbe     short loc_6D5D15
            83 EC 1C                    // sub     esp, 1Ch
            C6 44 24 1A ??              // mov     [esp+1Ch+var_2], 62h ; 'b'
            C6 44 24 19 ??              // mov     [esp+1Ch+var_3], 58h ; 'X'
            C6 44 24 1B 00              // mov     [esp+1Ch+var_1], 0
            31 C0                       // xor     eax, eax
            EB 0C                       // jmp     short loc_6D5CC4
        }
    condition:
        pe.is_32bit()
        and for 1 i in (1..#colon) : (
                uint8(@colon[i] + 25) ^ uint8(@colon[i] + 30) == 0x3a // ':'
            )
}

rule deimosc2_agent_win32_https_obfuscated {
    meta:
        description = "Detects HTTPS samples by the presence of http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $http_Post = {
            E8 ?? ?? ?? 00                 // call    net_http_NewRequestWithContext
            8B 44 24 20                    // mov     eax, [esp+40h+var_20]
            8B 4C 24 24                    // mov     ecx, [esp+40h+var_1C]
            8B 54 24 28                    // mov     edx, [esp+40h+var_18]
            85 C9                          // test    ecx, ecx
            0F 85 F4 00 00 00              // jnz     loc_6203AB
            89 44 24 30                    // mov     [esp+40h+var_10], eax
            8B 48 1C                       // mov     ecx, [eax+1Ch]
            89 4C 24 3C                    // mov     [esp+40h+var_4], ecx
            90                             // nop
            8D 15 ?? ?? ?? 00              // lea     edx, aContentType ; "Content-Type"
            89 14 24                       // mov     [esp+40h+var_40], edx ; int
            C7 44 24 04 0C 00 00 00        // mov     [esp+40h+var_3C], 0Ch ; int
            E8 ?? ?? ?? FF                 // call    net_textproto_CanonicalMIMEHeaderKey
        }

    condition:
        deimosc2_agent_win32_colon_decrypt_obfuscated
        and all of them
}

rule deimosc2_agent_win32_tcp_obfuscated {
    meta:
        description = "Detects TCP samples by the presence of net.Dial() but no http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $http_Post = {
            E8 ?? ?? ?? 00               //                 call    net_http_NewRequestWithContext
            8B 44 24 20                  //                 mov     eax, [esp+40h+var_20]
            8B 4C 24 24                  //                 mov     ecx, [esp+40h+var_1C]
            8B 54 24 28                  //                 mov     edx, [esp+40h+var_18]
            85 C9                        //                 test    ecx, ecx
            0F 85 F4 00 00 00            //                 jnz     loc_6203AB
            89 44 24 30                  //                 mov     [esp+40h+var_10], eax
            8B 48 1C                     //                 mov     ecx, [eax+1Ch]
            89 4C 24 3C                  //                 mov     [esp+40h+var_4], ecx
            90                           //                 nop
            8D 15 ?? ?? ?? 00            //                 lea     edx, aContentType ; "Content-Type"
            89 14 24                     //                 mov     [esp+40h+var_40], edx ; int
            C7 44 24 04 0C 00 00 00      //                 mov     [esp+40h+var_3C], 0Ch ; int
            E8 ?? ?? ?? FF               //                 call    net_textproto_CanonicalMIMEHeaderKey
        }

    condition:
        deimosc2_agent_win32_colon_decrypt_obfuscated
        and not $http_Post
}
