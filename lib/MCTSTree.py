# coding=UTF-8

import math

"""
MCTS data structure
"""

class MCTSNode(object):
    """
    store data in MCTS Tree
    """
    def __init__(self, parent=None, coverage=None, data=None, child=None):
        self.parent = parent
        self.coverage = coverage if coverage != None else 0
        self.type = "Expandable"
        self.data = data
        self.visit = 0
        self.child = child if child != None else []

    def __str__(self):
        return "<MCTSNode(%9s) Data:%4s Coverage:%2d Parent:%4s>" \
        % (self.type, self.data, self.coverage, \
        self.parent.data if self.parent != None else "None")

    def is_expandable(self):
        """
        This node's coverage is fully simulated or deduce by its children
        """
        return self.type == "Expandable"

    def is_terminated(self):
        return self.type == "Terminated"

    def refresh_coverage(self):
        """
        calculate average coverage from children
        """
        self.visit += 1
        if len(self.child) != 0:
            _sum = 0
            somebody_alive = False
            for child in self.child:
                _sum += child.coverage
                if not child.is_terminated():
                    somebody_alive = True 
            self.coverage = _sum / (float)(len(self.child))
            self.type = "Visited" if somebody_alive else "Terminated"
        else:
            self.type = "Terminated"

    def best_child(self, c):
        max_child_val = -1
        max_child = None
        for child in self.child:
            if child.is_terminated():
                continue
            val = child.coverage/float(child.visit) + \
                  c * math.sqrt(2 * math.log10(self.visit) / float(child.visit)) \
                  if child.visit != 0 else 9999
            if val > max_child_val:
                max_child_val = val
                max_child = child
        return max_child

class MCTSTree(object):
    """
    store data in MCTS Tree
    """
    def __init__(self):
        self.root = MCTSNode(data="Root")
        self.current = self.root

    def debug(self):
        """
        print tree
        """
        def print_node(tnode, depth):
            print "--%d: %s" % (depth, tnode)
        print_node(self.root, 1)
        self.__bfs(print_node, self.root)

    def __bfs(self, callback, tnode, depth=1):
        if tnode is None or tnode.child is None or len(tnode.child) == 0:
            return
        for child in tnode.child:
            callback(child, depth+1)
        for child in tnode.child:
            self.__bfs(callback, child, depth+1)

    def select_node(self, node=None):
        """
        從MCTSTree中挑選最好的Node (TreePolicy)
        """
        node = self.root if node is None else node
        while not node.is_terminated():
            if node.is_expandable():
                self.current = node
                return node
            else:
                node = node.best_child(9/math.sqrt(2))
                # print "Pick: %s" % node.data

    def add_child(self, data=None, coverage=None):
        """
        加入child到current selected node中
        """
        self.current.child.append(MCTSNode(parent=self.current, data=data, coverage=coverage))

    def refresh_tree(self):
        """
        更新current node的狀態
        """
        while self.current != None:
            self.current.refresh_coverage()
            self.current = self.current.parent


if __name__ == '__main__':
    tree = MCTSTree()

    print "Empty Tree:"
    tree.debug()

    print ""

    node = tree.select_node()
    print "Selected Node: %s" % node.data
    print "Add 2 Node"
    tree.add_child(data="A0", coverage=80)
    tree.add_child(data="A1", coverage=60)
    tree.refresh_tree()
    tree.debug()

    print ""

    node = tree.select_node()
    print "Selected Node: %s" % node.data
    print "Add 0 Node"
    tree.refresh_tree()
    tree.debug()

    print ""

    node = tree.select_node()
    print "Selected Node: %s" % node.data
    print "Add 3 Node"
    tree.add_child(data="C0", coverage=40)
    tree.add_child(data="C1", coverage=30)
    tree.add_child(data="C2", coverage=50)
    tree.refresh_tree()
    tree.debug()

    print ""

    node = tree.select_node()
    print "Selected Node: %s" % node.data
    print "Add 2 Node"
    tree.add_child(data="D0", coverage=50)
    tree.add_child(data="D1", coverage=55)
    tree.refresh_tree()
    tree.debug()
    
    print ""

    node = tree.select_node()
    print "Selected Node: %s" % node.data
    print "Add 0 Node"
    tree.refresh_tree()
    tree.debug()
 
    print ""

    node = tree.select_node()
    print "Selected Node: %s" % node.data
    print "Add 0 Node"
    tree.refresh_tree()
    tree.debug()

    print ""

    node = tree.select_node()
    print "Selected Node: %s" % node.data
    print "Add 0 Node"
    tree.refresh_tree()
    tree.debug()

    print ""

    node = tree.select_node()
    print "Selected Node: %s" % node.data
    print "Add 0 Node"
    tree.refresh_tree()
    tree.debug()


 




