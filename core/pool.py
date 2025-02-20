import config
import multiprocessing

class PredatorPool:

  def __init__(self, nome_thread, target, args, autostart):
    self.nome_thread = nome_thread
    self.target = target
    self.args = args
    self.thread = multiprocessing.Process(target=self.target, args=self.args)
    #self.thread.setDaemon(True)
    self.stato = ""
    if autostart:
      self.start()

  def get_thread(self):
    return self.thread

  def start(self):
    self.thread.start()
    self.stato = "started"

  def join(self):
    self.thread.join()

  def stop(self):
    self.stato = "stopped"

