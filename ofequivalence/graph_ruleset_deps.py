#!/usr/bin/python
"""
Builds a graph showing the dependencies between rules in a ruleset.

Black edges indicate dependencies between rules within a table.
Red edges indicate dependencies between rule in different tables.

For any rule a dependency exists with another higher priority rule if it
directly shadows traffic from reaching it. NOTE: if two high priority rules
exist which filter the shadow the same packet-space from reaching the
rule only the lowest priority has a dependency drawn. However, the highest
priority and lowest priority rules will have a dependency.

E.g.

R1  (P:1000   M:TCP:80, IP:1.1.1.1)
R2  (P:900    M:TCP:80)
R3  (P:0      M: *)

Results in the dependencies R1 <-> R2 and R2 <-> R3. But not R1 <-> R3.


Between tables we draw a dependency for all rules that goto another table.
The packet-space after any modifications applied is used to find the rules hit.

For dot:
Cluster: The displayed group, a group will be placed on the same rank
Group: Sorting groups, used to force cluster to be placed in new ranks, even
       if deps don't force this. For example make sure a new table starts on
       a new rank.
       A group must include one or more clusters.

"""

from __future__ import print_function
import sys
import argparse
import json
import time
from itertools import groupby
from collections import defaultdict
from tempfile import NamedTemporaryFile

import networkx as nx
from networkx.readwrite import json_graph

from ofequivalence.convert_ryu import ruleset_from_ryu
from ofequivalence.convert_fib import ruleset_from_fib
from ofequivalence.rule import Rule
from ofequivalence.ruleset import (sort_ruleset, compress_ruleset,
                                   create_similar_groups,
                                   sort_key_ruleset_priority)
from ofequivalence.utils import nullcontext, AlphaInt
from ofequivalence import ruleset_deps_direct
from ofequivalence import ruleset_deps_indirect


# D3 web page template
D3_HTML = """<meta charset="utf-8"/><!DOCTYPE html>
<html>
    <head>
        <title>Graph</title>
        <script type="text/javascript"
          src="https://cdnjs.cloudflare.com/ajax/libs/d3/3.4.11/d3.min.js">
        </script>
        <style>
        circle.node {{
         stroke: #fff;
         stroke-width: 1.5px;
        }}

        line.link {{
         stroke: #999;
         stroke-opacity: .6;
        }}
        </style>
    </head>
    <body>
        <div id="chart"></div>
        <script type="text/javascript">

var WIDTH = 1500,
    HEIGHT = 800,
    fill = d3.scale.category20();

var vis = d3.select("#chart")
  .append("svg:svg")
    .attr("width", WIDTH)
    .attr("height", HEIGHT);
json = {};
for(key in json.nodes) {{
    node = json.nodes[key]
    node.x = node.pos[0] * WIDTH;
    node.y = node.pos[1] * -HEIGHT + HEIGHT;
    node.fixed = true;
}}
var color = d3.scale.category20();
  var force = d3.layout.force()
      .charge(-120)
      .linkDistance(30)
      .nodes(json.nodes)
      .links(json.links)
      .size([WIDTH, HEIGHT])
      .start();

  var link = vis.selectAll("line.link")
      .data(json.links)
    .enter().append("svg:line")
      .attr("class", "link")
      .style("stroke-width", function(d) {{ return Math.sqrt(d.value); }})
      .style("stroke", function(d) {{ return d.color; }})
      .attr("x1", function(d) {{ return d.source.x; }})
      .attr("y1", function(d) {{ return d.source.y; }})
      .attr("x2", function(d) {{ return d.target.x; }})
      .attr("y2", function(d) {{ return d.target.y; }});

  var node = vis.selectAll("circle.node")
      .data(json.nodes)
    .enter().append("svg:circle")
      .attr("class", "node")
      .attr("cx", function(d) {{ return d.x; }})
      .attr("cy", function(d) {{ return d.y; }})
      .attr("r", 5)
      .attr("fill", function(d) {{return d.fillcolor;}})
      .call(force.drag);

  node.append("svg:title")
      .text(function(d) {{ return d.d3name; }});

  vis.style("opacity", 1e-6)
    .transition()
      .duration(1000)
      .style("opacity", 1);

  force.on("tick", function() {{
    link.attr("x1", function(d) {{ return d.source.x; }})
        .attr("y1", function(d) {{ return d.source.y; }})
        .attr("x2", function(d) {{ return d.target.x; }})
        .attr("y2", function(d) {{ return d.target.y; }});

    node.attr("cx", function(d) {{ return d.x; }})
        .attr("cy", function(d) {{ return d.y; }});
  }});
        </script>
    </body>
</html>
"""

# File extension for the different output types
FILE_EXT = {
        "d3": ".html",
        "dotpdf": ".pdf",
        "dotraw": ".dot",
        }


def parse_args():
    """ Parse command line arguments """

    parser = argparse.ArgumentParser(
        description='Plots the dependencies of a ruleset.\n'
                    'By default, opens the visualisation automatically.\n'
                    'Each node represents a rule, and each edge a dependency. '
                    'A black edge represents a shadow dependency within the '
                    'same table, and a red edge is a dependency between tables.'
        )

    parser.add_argument('filein',
                        help='A ruleset')
    parser.add_argument('-t', '--type', choices=["dotraw", "dotpdf", "d3", "pyplot"],
                        default="pyplot", help="Select the output format")
    parser.add_argument('-d', '--dependencies', default="direct",
                        choices=["direct", "indirect"],
                        help='Show and compute using direct or indirect dependencies')
    parser.add_argument('-c', '--cluster', default="none",
                        choices=["none", "compressed", "priority", "table"],
                        help='Create clusters in separate boxes (dot only)')
    parser.add_argument('-g', '--group', default="none",
                        choices=["none", "compressed", "priority", "table"],
                        help='Group into separate layers/ranks down the graph')
    parser.add_argument('--compress', action='store_true',
                        help="Run compress on the ruleset and highlight the "
                             "selected rules (the light-blue nodes)")
    parser.add_argument('--only-group', action='store_true',
                        help="Find groups for compression but do not pick a final rule."
                             " For when the picking a rule is not possible.")
    parser.add_argument('-m', '--no-table-miss', action='store_true',
                        help="Don't display table-miss rules")
    parser.add_argument('-f', '--fib', action='store_true',
                        help="Loads a FIB and enables optimisations")
    parser.add_argument('--node-label',
                        help="format() a node, extra z or Z modifier for alpha")
    parser.add_argument('--group-label',
                        help="format() a node, extra z or Z modifier for alpha")
    parser.add_argument('-o', '--output',
                        help="Save the result to the given file")
    parser.add_argument('-O', '--output-only', action='store_true',
                        help="Do not try and display the result")
    args = parser.parse_args()

    if args.type == "pyplot" and (args.output_only or args.output):
        parser.print_usage()
        print("Pyplot cannot write an output file")
        print("Remove any -o,--output and -O,--output-only options")
        exit()

    if args.type not in ("dotraw", "dotpdf") and args.cluster != "none":
        print("Warning: cluster option ignored for", args.type, file=sys.stderr)
    elif args.cluster != "none" and args.group != "none":
        print("Warning: group option will be ignored due to cluster option",
              file=sys.stderr)


    # Set the default labels
    if args.node_label is None:
        if args.type in ("dotpdf", "dotraw"):
            args.node_label = "<R<SUB>{:Z}</SUB>>"
        else:
            args.node_label = "{:Z}"
    if args.group_label is None:
        if args.type in ("dotpdf", "dotraw"):
            args.group_label = "<G<SUB>{}</SUB>>"
        else:
            args.group_label = "G{}"

    return args


def directed_layout(graph, scale=1.0, push_down=True, cluster=True, key=None):
    """ Create a directed layout from top to bottom.

        This layout ensures that all children are placed on lower levels
        than their parents.

        graph: The NetworkX graph - nodes are expected to contain the table
           attribute if separate table is set.
        scale: The nodes are positioned with a box of size [0, scale]
               x [0, scale]
        push_down: If True, nodes are placed at the lowest possible point in
                   the graph, i.e. directly above their closest parent.
                   Otherwise they are placed at the highest position
                   possible within the graph.
        cluster: Apply a very simple clustering algorithm to try and group
                 nodes with the same destination close to each other and
                 close to their descendants.
        key: How to sort rules from high to low priority, by default we assume
             Rules are being used.
    """
    def _layout(nodes, key):
        levels = []
        if key is None:
            key = sort_key_ruleset_priority
        for to_add in sorted(nodes, key=key):
            edges_in = [e[0] for e in graph.edges() if e[1] == to_add]
            next_level = -1
            # We find the level at which we can place this
            # on level below its lowest parent
            for l_index, level in enumerate(levels):
                for node in level:
                    if node in edges_in:
                        next_level = l_index
            next_level += 1
            if len(levels) <= next_level:
                levels.append([])
            levels[next_level].append(to_add)

        # Now push down any which do not have anything under them, starting at
        # the bottom and working up
        # We find that the top row is normally the largest, so we move down
        # those with no connections
        if push_down:
            for l_index in reversed(range(0, len(levels)-1)):
                n_index = 0
                while n_index < len(levels[l_index]):
                    for dst in [e[1] for e in graph.edges()
                                if e[0] == levels[l_index][n_index]]:
                        if dst in levels[l_index+1]:
                            n_index += 1
                            break
                    else:
                        # move down
                        levels[l_index+1].append(levels[l_index][n_index])
                        del levels[l_index][n_index]

        return levels

    levels = []

    # Enforce level separation between groups
    # NOTE: Within a group there might be multiple levels from dependencies
    if 'group' in graph.nodes[next(iter(graph.nodes()))]:
        tables = {graph.node[x]['group'] for x in graph.nodes()}
        for table in sorted(tables):
            table_nodes = [x for x in graph.nodes() if graph.node[x]['group'] == table]
            levels += _layout(table_nodes, key)
    else:
        levels = _layout(graph.nodes(), key)

    # Try to cluster sort such that the line below is about right
    # the final level is in fixed positions
    # The level above is sorted left to right depending upon deps on the final
    if cluster:
        for level, next_level in reversed(list(zip(levels, levels[1:]))):
            def generate_sort_level(node):
                m_index = 99999999999999
                for dst in [e[1] for e in graph.edges() if e[0] == node]:
                    if dst in next_level:
                        m_index = min(m_index, next_level.index(dst))
                return m_index
            level.sort(key=generate_sort_level)

    # Spread out nodes evenly based on the number of levels and nodes within
    # each level
    positions = {}
    for l_index, level in enumerate(levels):
        y = 1.0 - (1.0 / float(len(levels))) * (l_index + 0.5)
        for n_index, node in enumerate(level):
            x = (1.0 / float(len(level))) * (n_index + 0.5)
            positions[node] = (x*scale, y*scale)

    return positions


def build_graph(ruleset, args):
    """ Builds the NetworkX graph

        Builds the NetworkX for the ruleset showing dependencies
    """

    if args.dependencies == "direct":
        dep_lib = ruleset_deps_direct
    else:
        dep_lib = ruleset_deps_indirect

    ruleset = sort_ruleset(ruleset)
    if args.fib:
        deps = dep_lib.build_prefix_table_deps(ruleset)
    else:
        deps = dep_lib.build_ruleset_deps(ruleset)

    if args.no_table_miss:
        ruleset = [rule for rule in ruleset if rule.priority != 0]
        deps = [e for e in deps if e[0].priority != 0 and e[1].priority != 0]

    if args.compress:
        if args.only_group:
            min_groups, _ = create_similar_groups(ruleset, deps=deps)
            min_ruleset = []
        else:
            min_ruleset, min_groups = compress_ruleset(ruleset, deps=deps)

    # Build our graph object
    G = nx.DiGraph()
    G.add_edges_from(((src, dst) for src, dst in deps if src.table == dst.table),
                     color="black")
    G.add_edges_from(((src, dst) for src, dst in deps if src.table != dst.table),
                     color="red", style="dashed")

    # Add a label to all rules
    label_dict = {}
    reachables = []
    for i, rule in enumerate(ruleset):
        try:
            G.node[rule]['table'] = rule.table
            rule.label = args.node_label.format(AlphaInt(i))
            label_dict[rule] = rule.label
            G.node[rule]['label'] = rule.label
            if args.type == 'd3':
                G.node[rule]['d3name'] = rule.label + " " + str(rule)
            if args.type in ('dotpdf', 'dotraw'):
                G.node[rule]['tooltip'] = str(rule).replace("\n", "<BR/>")
            G.node[rule]['priority'] = rule.priority
            G.node[rule]['table'] = rule.table
            # Label with number and print mapping
            print(rule.label, '\t', str(rule), file=sys.stderr)
            reachables.append(rule)
        except KeyError:
            print('Unreachable:', '\t', str(rule), file=sys.stderr)
            if args.compress:
                min_ruleset.remove(rule)
                del min_groups[rule]
    ruleset[:] = reachables
    # Remove unreachable rules

    # Create clusters and groups
    if args.cluster == "priority":
        number_groups(groupby(ruleset, key=sort_key_ruleset_priority), "cluster", G)
    elif args.cluster == "table":
        number_groups(groupby(ruleset, key=lambda r: r.table), "cluster", G)
    elif args.cluster == "compressed":
        groups = [(None, min_groups[group]) for group in sort_ruleset(min_groups)]
        number_groups(groups, "cluster", G)

    if args.group == "priority":
        number_groups(groupby(ruleset, key=sort_key_ruleset_priority), "group", G)
    elif args.group == "table":
        number_groups(groupby(ruleset, key=lambda r: r.table), "group", G)
    elif args.group == "compressed":
        groups = [(None, min_groups[group]) for group in sort_ruleset(min_groups)]
        number_groups(groups, "group", G)

    if args.type in ('pyplot', 'd3'):
        pos = directed_layout(G)
        for node in G:
            G.node[node]['pos'] = pos[node]


    if args.compress:
        for selected in min_ruleset:
            G.node[selected]['fillcolor'] = 'skyblue'
            G.node[selected]['style'] = 'filled'

    return G


def main():
    """ Entry point for ruleset graphing """
    args = parse_args()

    # Load the ruleset
    if args.fib:
        ruleset = ruleset_from_fib(args.filein)
    else:
        ruleset = ruleset_from_ryu(args.filein)

    graph = build_graph(ruleset, args)

    # Get the output file

    ctx = nullcontext()
    if not args.output and not args.output_only and args.type in FILE_EXT:
        ctx = NamedTemporaryFile(prefix="ofequiv", suffix=FILE_EXT[args.type], delete=True)

    with ctx as tmpfile:
        if args.output:
            output = args.output
        elif args.output_only or args.type not in FILE_EXT:
            output = None
        else:
            output = tmpfile.name

        if args.type == "pyplot":
            create_pyplot(graph)
        elif args.type == "d3":
            create_d3(graph, output)
        elif args.type == "dotpdf":
            create_dot_pdf(graph, args, output)
        elif args.type == "dotraw":
            create_dot_raw(graph, args, output)

        # If a file was written open it
        if not args.output_only and output:
            display_file(output)
            # Delay so the viewing application has time to open the file
            # before unlinking a temporary file
            time.sleep(5)


def number_groups(groups, label, graph):
    """
        Associate groups of rules with a unique number starting from 1.

        groups: A iterable of groups
        label: Adds the label to each node with the group number
               Normally, 'cluster' or 'group'
        graph: The NetworkX graph, adds node[label] = id
    """
    _id = 1
    for _, rules in groups:
        for rule in rules:
            graph.node[rule][label] = _id
        _id += 1

def reorder_dot(items, sort_key):
    """ Sort a dot graph defines into the specified order """
    sequences = sorted([i.get_sequence() for i in items], reverse=True)
    for item in sorted(items, key=sort_key):
        item.set_sequence(sequences.pop())


def create_dot(graph, args):
    """ Create a graphviz plot """
    import pydot

    def new_str(self):
        return self.label
    Rule.__str__ = new_str
    def add_constraint(graph, src, dst):
        """ Add a constraint/invisible edge to a pydot graph
            to try force nodes below another.
        """
        # Don't re-add a rule twice
        if not graph.get_edge(src.get_name(), dst.get_name()):
            graph.add_edge(pydot.Edge(src, dst, style="invisible",
                                      arrowhead="none"))
    dot_graph = nx.nx_pydot.to_pydot(graph)
    clusters = defaultdict(set)
    groups = defaultdict(set)

    # Get all nodes and set their sequence for consistent ordering
    reorder_dot(dot_graph.get_nodes(), lambda a: a.get_name())
    reorder_dot(
        dot_graph.get_edges(),
        lambda a: (dot_graph.get_node(a.get_source())[0].get_sequence(),
                   dot_graph.get_node(a.get_destination())[0].get_sequence()))

    for node in dot_graph.get_nodes():
        if args.cluster != "none":
            cluster = node.get_attributes()['cluster']
            clusters[cluster].add(node)
        if args.group != "none":
            group = node.get_attributes()['group']
            groups[group].add(node)
    if args.cluster != "none":
        for cluster, nodes in sorted(clusters.items(), key=lambda x: int(x[0])):
            subgraph = pydot.Cluster(cluster)
            subgraph.set_label(args.group_label.format(AlphaInt(cluster)))
            subgraph.set_rank("same")
            for node in nodes:
                subgraph.add_node(pydot.Node(node.get_name()))
            dot_graph.add_subgraph(subgraph)

    if args.group != "none":
        node = None
        for cluster, nodes in sorted(groups.items(), key=lambda x: int(x[0])):
            if node:
                add_constraint(dot_graph, node, next(iter(nodes)))
            node = next(iter(nodes))

    # Remove the margin, do this last otherwise subgraphs/clusters inherit it
    dot_graph.set_graph_defaults(margin="0")
    return dot_graph


def create_dot_pdf(graph, args, output):
    """ Output a dot rendered to PDF """
    from subprocess import Popen, PIPE
    dot_graph = create_dot(graph, args)
    if output:
        proc = Popen(['dot', '-Tpdf', '-o', output], stdin=PIPE)
        proc.communicate(str(dot_graph).encode())
        proc.wait()
    else:
        proc = Popen(['dot', '-Tpdf'], stdin=PIPE)
        proc.communicate(str(dot_graph).encode())
        proc.wait()


def create_dot_raw(graph, args, output):
    """ Output a dot file """
    dot_graph = create_dot(graph, args)
    if output:
        with open(output, "w") as fout:
            fout.write(str(dot_graph))
    else:
        print(str(dot_graph))


def display_file(name):
    """ Open a file using the default system viewer """
    from subprocess import Popen
    Popen(['xdg-open', name])


def create_d3(graph, output):
    """ Create a d3 graph as a webpage """
    # Set the position of the links and names for the links
    # As these are shown on however the full name can be used
    data = json_graph.node_link_data(graph)
    for l in data["links"]:
        l['source'] = [x['id'] for x in data['nodes']].index(l['source'])
        l['target'] = [x['id'] for x in data['nodes']].index(l['target'])
    # The id is filled with the rule, which can not be jsonified
    for node in data['nodes']:
        del node['id']
    html = D3_HTML.format(json.dumps(data))

    if output:
        with open(output, "w") as f_out:
            f_out.write(html)
    else:
        print(html)


def create_pyplot(graph):
    """ Create and plot the NetworkX graph using pyplot """

    import matplotlib.pyplot as plt
    # graph.nodes and graph.edges return a consistent order
    nx.draw_networkx(graph,
                     labels=dict(graph.nodes(data='label')),
                     pos=dict(graph.nodes(data='pos')),
                     node_color=[i[1] for i in graph.nodes(data='fillcolor', default='red')],
                     edge_color=[k for _, _, k in graph.edges(data='color')]
                    )
    plt.show()

if __name__ == "__main__":
    main()
