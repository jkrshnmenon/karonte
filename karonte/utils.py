from pathlib import Path
from random import randint

from libraries.extractor.extractor import Extractor


MAX_THREADS = 3
N_TYPE_DATA_KEYS = 4
CUR_PATH = Path(__file__).parent.parent
DEFAULT_LOG_PATH = CUR_PATH / "logs" / ("Karonte.txt_" + str(randint(1, 100)))
DEFAULT_PICKLE_DIR = CUR_PATH / "pickles/"
EXTRACED_FW_DIR = CUR_PATH / 'test_cases/'
PACKED_FW_DIR = CUR_PATH / 'firmwares/'


def unpack_firmware(fw_path, out_dir):
    """
    Unpacks the firmware
    :param fw_path:  firmware path
    :param out_dir: the directory to extract to
    :return: the path of the unpacked firmware, which is stored in the brand folder
    """
    input_file = fw_path

    # arguments for the extraction
    rootfs = True
    kernel = False
    enable_parallel = False
    enable_debug = False

    # extract the file to the provided output directory using the FirmAE extractor
    extract = Extractor(input_file, out_dir, rootfs,
                        kernel, enable_parallel, enable_debug)
    extract.extract()

    return out_dir
