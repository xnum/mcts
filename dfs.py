from . import ExplorationTechnique
import random
import logging
import math 

l = logging.getLogger('angr.DFS')

class DFS(ExplorationTechnique):
    """
    Depth-first search.

    Will only keep one path active at a time, any others will be stashed in the 'deferred' stash.
    When we run out of active paths to step, we take the longest one from deferred and continue.
    """
    def __init__(self, project):
        l.info("Init CFG")
        self.cfg = project.analyses.CFGFast(normalize=True)
        l.info("finding loop")
        self.loops = project.analyses.LoopFinder().loops
        self.total_nodes = len(self.cfg.graph.nodes())
        self.total_cover = set()
        self.count = 0
        random.seed()

    def setup(self, pg):
        if 'deferred' not in pg.stashes:
            pg.stashes['deferred'] = []
        if 'income' not in pg.stashes:
            pg.stashes['income'] = []

    def step(self, pg, stash, **kwargs):

        self.count = self.count + 1
        self.total_cover.update(self._get_past_hist(pg.stashes[stash][0]))

        pg = pg.step(stash=stash, **kwargs)


        if len(pg.stashes[stash]) >= 1:
            for a in pg.stashes[stash]:
                a.info.clear()
            pg.stashes['income'].extend(pg.stashes[stash][:])
            del pg.stashes[stash][:]

        for a in pg.stashes['income']:
            if 'rate' not in a.info:
                a.info['rate'] = []
                a.info['cover'] = self._get_past_hist(a)
                a.info['pick'] = 1
                a.info['val'] = 1
                for times in range(50):
                    hist = self.simulation(a)
                    a.info['rate'].append(len(hist))

        pg.stashes['deferred'].extend(pg.stashes['income'][:])
        del pg.stashes['income'][:]

        if len(pg.stashes[stash]) == 0:
            if len(pg.stashes['deferred']) == 0:
                return pg
            if pg._dfs:
                i, deepest = max(enumerate(pg.stashes['deferred']), key=lambda l: len(l[1].trace))
            else:
                i, deepest = self.pick_best(pg.stashes['deferred'])
            pg.stashes['deferred'].pop(i)
            pg.stashes[stash].append(deepest)

        if self.count % 50 == 0:
            l.info(pg)
            l.info("DATA %s Round %d block %d","DFS" if pg._dfs else "MCTS",self.count,len(self.total_cover))

        return pg

    def selection(self, pg, stash, times):
        def cal_val(pg, a):
            avg_cover = sum(a.info['rate']) / float(len(a.info['rate'])) if len(a.info['rate']) != 0 else len(a.info['cover'])
            avg_reward = avg_cover / float(self.total_nodes)
            exp_value = math.sqrt( 2*math.log10(times) / float(a.info['pick']) )
            res = avg_reward + exp_value
            a.info['val'] = res
            return res
        max_val = 0
        max_i = 0
        for i in range(0,len(pg.stashes['deferred'])):
            val = cal_val(pg, pg.stashes['deferred'][i])
            #l.info("%d %lf",i ,val)
            if val > max_val:
                max_i = i
                max_val = val
        highest = pg.stashes['deferred'][max_i]
        highest.info['pick'] = highest.info['pick'] + 1
        return max_i, highest
        '''
        i = random.randint(0,len(pg.stashes['deferred'])-1)
        return i, pg.stashes['deferred'][i]
        '''

    def pick_best(self, stashes):
        max_val = 0
        max_i = 0
        for i in range(0,len(stashes)):
            val = sum(stashes[i].info['rate']) / float(len(stashes[i].info['rate']))
            if val > max_val:
                max_i = i
                max_val = val
        highest = stashes[max_i]
        return max_i, highest
        '''
        i = random.randint(0,len(stashes)-1)
        return i, stashes[i]
        '''



    def simulation(self, path):
        addr_hist = path.info['cover']
        addr_hist.add(path.addr)
        addr_hist.update(self._simulate_future(path.addr))

        return addr_hist

    def backpropagation(self, pg, i, addr_hist):

        # find = self.cfg.get_any_node(pg._find,anyaddr=True) if pg._find is None else None
        find = None
        if find is not None and find.addr in addr_hist:
            #l.info("touch find")
            pg.stashes['deferred'][i].info['rate'].append(self.total_nodes)
        else:
            pg.stashes['deferred'][i].info['rate'].append(len(addr_hist))
        return

    def _get_past_hist(self, path):
        addr_hist = set()

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
        while True:
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



