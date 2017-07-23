import time
import string
import random
# import logging as log
from ete3 import Tree  # , TreeStyle
from ete3.parser.newick import NewickError


def timeit(f):
    def a_wrapper_accepting_arguments(*args, **kargs):
        t1 = time.time()
        r = f(*args, **kargs)
        print(" %0.3f secs: %s" % (time.time() - t1, f.__name__))
        return r
    return a_wrapper_accepting_arguments


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


class WebTreeHandler(object):
    def __init__(self, newick, actions, style):
        if isinstance(newick, Tree):
            self.tree = newick
        else:
            try:
                self.tree = Tree(newick)
            except NewickError:
                self.tree = Tree(newick, format=1)

        self.tree.actions = actions
        self.tree.tree_style = style

        # Initialze node internal IDs
        for index, n in enumerate(self.tree.traverse('preorder')):
            n._nid = index

    @timeit
    def redraw(self):
        base64_img, img_map = self.tree.render("%%return.PNG", tree_style=self.tree.tree_style)
        nodes, faces = self.get_html_map(img_map)
        base64 = base64_img.data().decode()
        return nodes, faces, base64

    def get_html_map(self, img_map):
        nodes = []
        if img_map.get("nodes"):
            for x1, y1, x2, y2, nodeid, text in img_map["nodes"]:
                nodes.append([x1, y1, x2, y2, nodeid, text, img_map["node_areas"].get(int(nodeid), [0, 0, 0, 0])])
        faces = []
        if img_map.get("faces"):
            for x1, y1, x2, y2, nodeid, text in img_map["faces"]:
                faces.append([x1, y1, x2, y2, nodeid, text, img_map["node_areas"].get(int(nodeid), [0, 0, 0, 0])])
        return nodes, faces

    def get_avail_actions(self, nodeid):
        target = self.tree.search_nodes(_nid=int(nodeid))[0]
        action_list = []
        for aindex, aname, show_fn, run_fn in self.tree.actions:
            if show_fn(target):
                action_list.append([aindex, aname])
        return action_list

    def run_action(self, aindex, nodeid):
        target = self.tree.search_nodes(_nid=int(nodeid))[0]
        run_fn = self.tree.actions.actions[aindex][2]
        return run_fn(self.tree, target)


class NodeActions(object):
    def __str__(self):
        text = []
        for aindex, aname, show_fn, run_fn in self:
            text.append("%s: %s, %s, %s" % (aindex, aname, show_fn, run_fn))
        return '\n'.join(text)

    def __iter__(self):
        for aindex, (aname, show_fn, run_fn) in self.actions.items():
            yield (aindex, aname, show_fn, run_fn)

    def __init__(self):
        self.actions = {}

    def clear_default_actions(self):
        self.actions = {}

    def add_action(self, action_name, show_fn, run_fn):
        aindex = "act_" + id_generator()
        self.actions[aindex] = [action_name, show_fn, run_fn]
