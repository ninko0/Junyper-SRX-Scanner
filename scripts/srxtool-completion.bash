#!/usr/bin/env bash
# Bash tab-completion for "srxtool".
#
# Install (add one of these to ~/.bashrc, then open a new shell):
#   source /path/to/srxtool-go/scripts/srxtool-completion.bash
# or, system-wide (Debian/Ubuntu):
#   sudo cp scripts/srxtool-completion.bash /etc/bash_completion.d/srxtool
#
# Hand-written against cmd/srxtool/main.go's own flag definitions — no
# generator, no external completion framework, consistent with this
# project's stdlib-only constraint. If a flag is added there, add it
# here too; there is no other link between the two.
#
# Note: several srxtool subcommands take a positional <conf> file BEFORE
# their flags in the usage examples (e.g. "srxtool audit conf.xml
# --json a.json"), but cmd/srxtool's own reorderArgs lets flags come in
# any order — this completion always offers both the flags and, once a
# flag that wants a file is seen, filename completion, regardless of
# position.
#
# Also usable from zsh via bashcompinit — see srxtool-completion.zsh.

_srxtool_subcommands="inventory audit rename-suggest rename-apply cleanup"

_srxtool_flags_inventory="--json --xlsx --allow-empty"
_srxtool_flags_audit="--json --xlsx --fix --min-severity --allow-empty"
_srxtool_flags_rename_suggest="--dns --csv"
_srxtool_flags_rename_apply="--map --set --rollback"
_srxtool_flags_cleanup="--inventory --hitcount --only --exclude --include-deny --batch --set --rollback"

# Flags that take a file path as their value, per subcommand.
_srxtool_file_flags_inventory="--json --xlsx"
_srxtool_file_flags_audit="--json --xlsx --fix"
_srxtool_file_flags_rename_suggest="--csv"
_srxtool_file_flags_rename_apply="--map --set --rollback"
_srxtool_file_flags_cleanup="--inventory --hitcount --set --rollback"

_srxtool_completion() {
    local cur prev subcmd
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${_srxtool_subcommands} -h --help help" -- "$cur") )
        return 0
    fi

    subcmd="${COMP_WORDS[1]}"
    local subcmd_var="${subcmd//-/_}"

    if [[ "$subcmd" == "audit" && "$prev" == "--min-severity" ]]; then
        COMPREPLY=( $(compgen -W "CRITICAL HIGH MEDIUM LOW INFO" -- "$cur") )
        return 0
    fi

    local file_flags_var="_srxtool_file_flags_${subcmd_var}"
    if [[ " ${!file_flags_var} " == *" $prev "* ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
        return 0
    fi

    local flags_var="_srxtool_flags_${subcmd_var}"
    if [[ -n "${!flags_var}" ]]; then
        COMPREPLY=( $(compgen -W "${!flags_var} -h" -- "$cur") )
        return 0
    fi

    # No known flag list for this word yet (e.g. it's the <conf> file
    # position): offer filenames as a sane default.
    COMPREPLY=( $(compgen -f -- "$cur") )
}

complete -F _srxtool_completion srxtool
