# coding: utf-8
import time
import os
from gateway import gateway_singleton, get_event_loop
from config import cg_debug

if __name__ == "__main__":
    if cg_debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)
        get_event_loop().set_debug(cg_debug)
    try:
        gateway_singleton.start()
    except Exception:
        # gateway_singleton.clearn()
        pass
    finally:
        # gateway_singleton.close()
        pass