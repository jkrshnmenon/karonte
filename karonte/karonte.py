import os
import json
import sys
import angr
import logging
from pathlib import Path

# import logging.config
# logging.config.dictConfig({
#     'version': 1,
#     'disable_existing_loggers': True,
# })
# 
# logging.getLogger("angr").disabled = True

from bf.bug_finder import BugFinder
from bbf.border_binaries_finder import BorderBinariesFinder
from bdg.binary_dependency_graph import BinaryDependencyGraph
from bdg.cpfs import environment, semantic, file, socket, setter_getter

from loggers.file_logger import FileLogger
from loggers.bar_logger import silence_angr
# from loggers.bar_logger import BarLogger
from utils import *



class Karonte:
    def __init__(self, config_path, log_path=None):
        self.log = logging.getLogger(self.__class__.__name__)
        self.log.setLevel(logging.DEBUG)
        silence_angr(self.log)

        self._config_path = config_path
        
        config = json.load(open(self._config_path))
        # remove empty keys from the config
        self._config = {k: v for k, v in config.items() if len(v) > 0}

        self._pickle_parsers = DEFAULT_PICKLE_DIR / self._config['pickle_parsers'] if 'pickle_parsers' in self._config else None

        self._border_bins = [str(x) for x in self._config['bin']] if 'bin' in self._config else []
        self.log.debug("Border bins: %s" % str(self._border_bins))

        self._fw_path = PACKED_FW_DIR / self._config['fw_path']
        self.log.info("Firmware path : %s" % self._fw_path)

        out_dir = EXTRACED_FW_DIR / self._fw_path.name

        if self._fw_path.is_file() and not out_dir.exists():
            owd = Path.cwd()

            self.log.info("Extracting firmware image. This may take a while...")
            self._fw_path = unpack_firmware(self._fw_path, EXTRACED_FW_DIR)
            self._fw_path = out_dir

            # the extractor messes up the working directory. reset it
            os.chdir(owd)

        elif self._fw_path.is_dir():
            self.log.info("Firmware is already extracted at %s" % self._fw_path)
            pass

        elif not self._fw_path.is_dir() and out_dir.exists():
            self.log.info("Firmware is already extracted at %s" % out_dir)
            # when the image is already extracted before and the passed directory is not the extracted dir
            self._fw_path = out_dir
        
        if log_path is None:
            if 'log_path' in self._config and len(self._config['log_path']) > 0:
                log_path = self._config['log_path']
            else:
                log_path = DEFAULT_LOG_PATH

        self._klog = FileLogger(self._fw_path, log_path)
        self._add_stats = 'true' == self._config['stats'].lower()

        self.log.info("Logging at: %s" % log_path)
        self.log.info("Firmware directory: %s" % self._fw_path)

    def run(self, analyze_parents=True, analyze_children=True):
        """
        Runs Karonte
        :return:
        """

        self._klog.start_logging()

        bbf = BorderBinariesFinder(self._fw_path, use_connection_mark=False)

        self.log.info("Retrieving Border Binaries")
        if not self._border_bins:
            self.log.info("Running BorderBinariesFinder")
            self._border_bins, pickle_file = bbf.run(pickle_file=self._pickle_parsers)
            self.log.info("Writing pickle file location to config file")
            self._config['pickle_parsers'] = pickle_file
            with open(self._config_path, "w") as f:
                json.dump(self._config, f, indent=2)
            if not self._border_bins:
                self.log.error("No border binaries found, exiting...")
                self.log.info(f"Finished, results in {self._klog.name}")
                self.log.complete()
                self._klog.close_log()
                return

        self.log.info("Generating Binary Dependency Graph")
        # starting the analysis with less strings makes the analysis faster
        pf_str = BorderBinariesFinder.get_network_keywords(end=N_TYPE_DATA_KEYS)
        cpfs = [environment.Environment, file.File, socket.Socket, setter_getter.SetterGetter, semantic.Semantic]
        bdg = BinaryDependencyGraph(self._config, self._border_bins, self._fw_path,
                                    init_data_keys=pf_str, cpfs=cpfs)
        bdg.run()
        print(bdg.graph)
        print(bdg.nodes)

        # self.log.info("Discovering Binary Dependency Graph")
        # bf = BugFinder(self._config, bdg, analyze_parents, analyze_children, logger_obj=log)
        # bf.run(report_alert=self._klog.save_alert, report_stats=self._klog.save_stats if self._add_stats else None)

        # self.log.info("Discovering Bugs")
        # bf = BugFinder(self._config, bdg, analyze_parents, analyze_children, logger_obj=log)
        # bf.run(report_alert=self._klog.save_alert, report_stats=self._klog.save_stats if self._add_stats else None)

        # Done.
        self.log.info(f"Finished, results in {self._klog.name}")
        # self.log.complete()

        if self._add_stats:
            self._klog.save_global_stats(bbf, bdg, bf)
        self._klog.close_log()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage " + sys.argv[0] + " config_path")
        sys.exit(0)

    config = sys.argv[1]
    log_file = sys.argv[2] if len(sys.argv) == 3 else DEFAULT_LOG_PATH
    so = Karonte(config, log_path=log_file)
    so.run()
