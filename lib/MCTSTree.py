# coding=UTF-8

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
        self.type = "Simulated"
        self.data = data
        self.child = child if child != None else []

    def __repr__(self):
        return "<MCTSNode(%9s) Data:%4s Coverage:%2d Parent:%4s>" \
        % (self.type, self.data, self.coverage, \
        self.parent.data if self.parent != None else "None")

    def is_simulated(self):
        """
        This node's coverage is fully simulated or deduce by its children
        """
        return self.type == "Simulated"

    def refresh_coverage(self):
        """
        calculate average coverage from children
        """
        _sum = 0
        for child in self.child:
            _sum += child.coverage
        self.coverage = _sum / (float)(len(self.child))
        self.type = "Actual"

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

    def select_node(self):
        """
        從MCTSTree中挑選最好的Node
        """
        self.current = self.root
        while True:
            if self.current.is_simulated():
                return self.current
            ptr = None
            for child in self.current.child:
                if ptr is None:
                    ptr = child
                if ptr.coverage < child.coverage:
                    ptr = child
            self.current = ptr

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


    print "\nAdd 2 Node"
    node = tree.select_node()
    tree.add_child(data="A0", coverage=80)
    tree.add_child(data="A1", coverage=60)
    tree.refresh_tree()
    tree.debug()

    print "\nAdd 1 Node"
    node = tree.select_node()
    tree.add_child(data="B0", coverage=70)
    tree.refresh_tree()
    tree.debug()

    print "\nAdd 3 Node"
    node = tree.select_node()
    tree.add_child(data="C0", coverage=40)
    tree.add_child(data="C1", coverage=30)
    tree.add_child(data="C2", coverage=50)
    tree.refresh_tree()
    tree.debug()

    print "\nAdd 2 Node"
    node = tree.select_node()
    tree.add_child(data="D0", coverage=50)
    tree.add_child(data="D1", coverage=55)
    tree.refresh_tree()
    tree.debug()
