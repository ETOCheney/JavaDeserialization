# coding=utf-8

import queue
import contextlib
import threading

WorkerStop = object()

class ThreadPool:
    workers = 0
    threadFactory = threading.Thread
    currentThread = staticmethod(threading.currentThread)

    def __init__(self,maxthreads=20,name=None):
        self.q = queue.Queue()  # 创建一个队列
        self.max = maxthreads  # 定义最大线程数
        self.name = name
        self.waiters = []  # 空闲的线程数量
        self.working = []  # 工作的线程数量

    def start(self):
        # q.size 为最大线程个数
        # works 默认为0
        needSize = self.q.qsize()
        while self.workers < min(self.max,needSize):
            self.startAWorker()

    def startAWorker(self):
        self.workers += 1  # workes 的数量+1
        # 创建一个线程并去执行_worker方法
        newThread = self.threadFactory(target=self._worker)
        newThread.start()

    def callInThread(self,func,*args,**kw):
        self.callInThreadWithCallback(None,func,*args,**kw)

    def callInThreadWithCallback(self,onResult,func,*args,**kw):
        o = (func,args,kw,onResult)
        self.q.put(o)

    # 定义上下文管理器
    @contextlib.contextmanager
    def _workerState(self,stateList,workerThread):
        stateList.append(workerThread)
        try:
            yield
        finally:
            stateList.remove(workerThread)

    def _worker(self):
        ct = self.currentThread()
        o = self.q.get()  # 去队列里面取任务，如果有任务o就会有值，每个任务是个元组，有方法，有参数
        while o is not WorkerStop:
            with self._workerState(self.working,ct): # 上下文切换
                function ,args,kwargs, onResult = o
                del o # 垃圾回收
                try:
                    result = function(*args,**kwargs)
                    success = True
                except:
                    success = False
                del function ,args,kwargs

                if onResult is not None:
                    try:
                        onResult(success, result)
                    except:
                        pass
                # del onResult, result
            with self._workerState(self.waiters, ct):
                o = self.q.get()  # 当进程工作完闲暇时，去取任务执行

    def stop(self):# 定义关闭线程的方法
        while self.workers: # 循环worsers的值
            self.q.put(WorkerStop) #
            self.workers -= 1   #
