import "elf"

/* 
 * Description: Ruleset for detecting Deimos C2 Windows agents
 * Author: Fernando Mercês @ Trend Micro FTR
 * 
 * Last updated: 2022-08-05
*/

global private rule deimos_elf {
    meta:
        description = "Detects structure of Deimos C2 agents for Linux"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"
    condition:
        elf.number_of_sections == 14
        and elf.sections[6].name == ".gosymtab"
        and filesize >= 6200000 and filesize <= 7600000
}

rule deimosc2_agent_linux {
    meta:
        description = "Detects non-obfuscated versions of Deimos C2 agents for Linux"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"
    strings:
        $empty_key = "000000000000000000000000000000000000"
        $sendMsg_drwap = {6D 61 69 6E 2E 73 65 6E 64 4D 73 67 C2 B7 64 77 72 61 70 C2 B7 32 00}
        $deimos = "github.com/DeimosC2/DeimosC2/agents/resources" 
    condition:
        any of them
        and #deimos > 10
}