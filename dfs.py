# coding=UTF-8

from . import ExplorationTechnique
import random
import logging
import math 
import os
from MCTSTree import *

l = logging.getLogger('angr.DFS')

class DFS(ExplorationTechnique):
    """
    Depth-first search.

    Will only keep one path active at a time, any others will be stashed in the 'deferred' stash.
    When we run out of active paths to step, we take the longest one from deferred and continue.
    """
    def __init__(self, project, method, limit):
        self.tree = MCTSTree()
        l.info("Init CFG")
        self.cfg = project.analyses.CFGFast(normalize=True)
        l.info("finding loop")
        self.loops = project.analyses.LoopFinder().loops
        self.total_nodes = len(self.cfg.graph.nodes())
        self.total_cover = set()
        self.count = 0
        self.method = method
        self.limit = limit
        self.last_print = 0
        self.fm = project.kb.functions
        open(os.path.basename(project.filename)+"_"+self.method+".txt",'w').close()
        self.fd = open(os.path.basename(project.filename)+"_"+self.method+".txt",'a')
        random.seed()
        l.info("init done")

    def setup(self, pg):
        if 'deferred' not in pg.stashes:
            pg.stashes['deferred'] = []
        if 'income' not in pg.stashes:
            pg.stashes['income'] = []

    def complete(self, pg):
        if self.count >= self.limit:
            if self.method != "MCTS":
                l.info("Done | %s Round %d/%d block %d/%d | %s", self.method ,self.count, self.limit, len(self.total_cover), self.total_nodes, pg)
            else:
                l.info("Done | %s Round %d/%d block %d/%d | %s deferred:%d", self.method ,self.count, self.limit, len(self.total_cover), self.total_nodes, pg, self.tree.count_living_node())
        return self.count >= self.limit

    def step(self, pg, stash, **kwargs):

        # 已經走過的路徑 加進total_cover裡
        self.count += len(pg.stashes[stash])
        self.total_cover.update(self._get_past_hist(pg.stashes[stash][0]))

        addr_before = pg.stashes[stash][0].addr
        addr_bef_name = self.fm.function(addr=addr_before)

        # expansion
        pg = pg.step(stash=stash, **kwargs)

        for a in pg.stashes[stash]:
            if addr_bef_name is None:
                self.fd.write("\"{0:#x}\" ->".format(addr_before))
            else:
                self.fd.write("\"{0}\" ->".format(addr_bef_name.name))

            addr_after_name = self.fm.function(addr=a.addr)
            if addr_after_name is None:
                self.fd.write("\"{0:#x}\"\n".format(a.addr))
            else:
                self.fd.write("\"{0}\"\n".format(addr_after_name.name))

        # move all path to income
        if len(pg.stashes[stash]) > 0 and self.method != "DEFAULT":
            for a in pg.stashes[stash]:
                a.info.clear()
            pg.stashes['income'].extend(pg.stashes[stash][:])
            del pg.stashes[stash][:]

        for a in pg.stashes['income']:
            if 'rate' not in a.info:
                a.info['rate'] = []
                a.info['cover'] = self._get_past_hist(a)
                for times in range(50):
                    hist = self.simulation(a)
                    a.info['rate'].append(len(hist))
                avg_cover = sum(a.info['rate']) / float(len(a.info['rate'])) \
                if len(a.info['rate']) != 0 else len(a.info['cover'])
                if self.method == "MCTS":
                    self.tree.add_child(data=a, coverage=avg_cover+len(a.trace))

        if self.method == "MCTS":
            self.tree.refresh_tree()

        if self.method != "MCTS":
            pg.stashes['deferred'].extend(pg.stashes['income'][:])
        del pg.stashes['income'][:]

        if len(pg.stashes[stash]) == 0:
            # if len(pg.stashes['deferred']) == 0:
            #     return pg
            if self.method == "DFS":
                i, deepest = max(enumerate(pg.stashes['deferred']), key=lambda l: len(l[1].trace))
                pg.stashes['deferred'].pop(i)
                pg.stashes[stash].append(deepest)
            elif self.method == "BFS":
                i, deepest = max(enumerate(pg.stashes['deferred']), key=lambda l: -len(l[1].trace))
                pg.stashes['deferred'].pop(i)
                pg.stashes[stash].append(deepest)
            elif self.method == "MCTS":
                node = self.tree.select_node()
                pg.stashes[stash].append(node.data)
            elif self.method == "DEFAULT":
                pass
            else:
                l.error("Unsupport method %s", self.method)

        if self.count - self.last_print >= 100:
            l.info(pg)
            l.info("Method %s Round %d/%d block %d", self.method ,self.count, self.limit, len(self.total_cover))
            self.last_print = self.count

        return pg

    def simulation(self, path):
        addr_hist = path.info['cover']
        addr_hist.add(path.addr)
        addr_hist.update(self._simulate_future(path.addr))
        # 模擬結果扣掉目前已經走過的blocks
        addr_hist.difference_update(self.total_cover)

        return addr_hist

    def _get_past_hist(self, path):
        addr_hist = set()

        #l.info(type(path))
        #l.info(path)
        it = iter(path.addr_trace)
        try:
            for i in it:
                addr_hist.add(i)
                next(it)
        except StopIteration:
            pass

        return addr_hist
        
    def _simulate_future(self, addr):
        addr_set = set()
        for i in range(0, 500):
            addr = self._decide_next_node(addr)
            if not addr:
                break
            addr_set.add(addr)
        return addr_set

    def _decide_next_node(self, addr):
        node = self.cfg.get_any_node(addr)
        if node == None:
            return False

        for loop in self.loops:
            if addr == loop.entry.addr:
                if random.randint(0,1) == 0:
                    if len(loop.break_edges) == 0:
                        return False
                    return random.choice(loop.break_edges)[1].addr
                else:
                    if len(loop.continue_edges) == 0:
                        return False
                    return random.choice(loop.continue_edges)[1].addr

        succs = node.successors 
        if len(succs) == 0:
            return False

        succ = random.choice(succs)
        return succ.addr

