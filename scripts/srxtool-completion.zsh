#!/usr/bin/env zsh
# Zsh tab-completion for "srxtool".
#
# Install: add to ~/.zshrc (adjust the path to where this repo lives):
#   source /path/to/srxtool-go/scripts/srxtool-completion.zsh
#
# Loads zsh's bash-compatibility layer and reuses srxtool-completion.bash
# directly — one source of truth for the flag list. Safe to source after
# your own `compinit` call elsewhere (autoload -U is idempotent).
autoload -Uz compinit && compinit
autoload -Uz bashcompinit && bashcompinit

_srxtool_completion_script_dir="${0:A:h}"
source "${_srxtool_completion_script_dir}/srxtool-completion.bash"
