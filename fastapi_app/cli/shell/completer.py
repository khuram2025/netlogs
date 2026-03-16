"""Nested tab-completion tree for the appliance CLI."""

from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document


# Command tree: nested dicts where leaves are None or a list of dynamic options
COMMAND_TREE = {
    "show": {
        "system": {
            "status": None,
            "health": None,
        },
        "interfaces": None,
        "services": None,
        "version": None,
        "disk": {
            "usage": None,
        },
        "logs": {
            "count": {
                "today": None,
                "week": None,
                "month": None,
                "all": None,
            },
        },
        "running-config": None,
    },
    "set": {
        "interface": "__interfaces__",  # Dynamic: list interfaces
        "dns": None,
        "hostname": None,
        "timezone": None,
        "ntp": None,
    },
    "request": {
        "system": {
            "reboot": None,
            "shutdown": None,
        },
        "backup": {
            "now": None,
        },
        "upgrade": {
            "local": None,
        },
        "factory-reset": None,
        "service": {
            "restart": {
                "web": None,
                "syslog": None,
                "nginx": None,
            },
        },
    },
    "help": None,
    "?": None,
    "exit": None,
    "quit": None,
    "logout": None,
}

# After selecting an interface, these are the next options
INTERFACE_ACTIONS = {
    "address": None,
    "gateway": None,
    "dhcp": None,
}


class ShellCompleter(Completer):
    """Tab-completion for the appliance CLI."""

    def get_completions(self, document: Document, complete_event):
        text = document.text_before_cursor
        words = text.split()

        # If text ends with space, we're completing the next word
        # Otherwise, we're completing the current partial word
        if text and not text.endswith(" "):
            partial = words[-1] if words else ""
            path_words = words[:-1]
        else:
            partial = ""
            path_words = words

        # Walk the command tree
        node = COMMAND_TREE
        for word in path_words:
            word_lower = word.lower()
            if isinstance(node, dict):
                if word_lower in node:
                    node = node[word_lower]
                else:
                    # No completions available
                    return
            else:
                return

        # Generate completions from current node
        if node is None:
            return

        if isinstance(node, str) and node == "__interfaces__":
            # Dynamic interface completion
            if not path_words or path_words[-1].lower() == "interface":
                # Complete interface names
                try:
                    from .network_config import list_interfaces
                    for iface in list_interfaces():
                        if iface.startswith(partial):
                            yield Completion(iface, start_position=-len(partial))
                except Exception:
                    pass
            else:
                # After interface name, complete actions
                for key in INTERFACE_ACTIONS:
                    if key.startswith(partial.lower()):
                        yield Completion(key, start_position=-len(partial))
            return

        if isinstance(node, dict):
            for key in sorted(node.keys()):
                if key.startswith(partial.lower()):
                    yield Completion(key, start_position=-len(partial))
