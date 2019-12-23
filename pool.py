from concurrent.futures import ProcessPoolExecutor
import functools
import logger

# TODO find elegant way to also include verbosity level here
# ? make logger part of the Pool class and use pool.logger.set_verbosity(3) from within recon4me ?
logger=logger.Logger(2)

class Pool(ProcessPoolExecutor):
    # custom subclass of ProcessPoolExecutor to be able to see how many processes are in the queue
    def __init__(self, *args, **kwargs):
        self._running_workers = 0
        self._max_workers=args[0]
        self._name=args[1]
        super().__init__(self._max_workers)
        logger.info("Created ProcessPool {self._name} with a maximum of {self._max_workers} concurrent processes")

    # leverages the ProcessPoolExecutor submit function to add workers to the queue
    # customisation is the added amount of running workers counter
    # *args, **kwargs is used to make viarable arguments length for different functions possible
    def submit(self, *args, **kwargs):
        future = super().submit(*args, **kwargs)
        self._running_workers += 1
        func=args[0].__name__
        future.add_done_callback(functools.partial(self._worker_is_done, func))
        logger.debug("{func} added to the queue, {bmagenta}{self._running_workers}{rst} workers still in the queue")
        return future

    # when a worker (added through the submit function) is done, callback is made to this
    # function and the workers in the queue are counted
    def _worker_is_done(self, *args, **kwargs):
        self._running_workers -= 1
        func = args[0]
        logger.debug("{func} is done, {bmagenta}{self._running_workers}{rst} workers still in the queue")

    #just for debugging
    def get_name(self):
        return self._name

    # returns the amount of workers in the queue
    def get_workers_in_queue(self):
        return self._running_workers