import sys

import logging
import json

import maltoolbox
import maltoolbox.cl_parser
from maltoolbox.language import classes_factory
from maltoolbox.language import specification
from maltoolbox.model import model
from maltoolbox.attackgraph import attackgraph
from maltoolbox.attackgraph.analyzers import apriori
from maltoolbox.ingestors import neo4j

# Load the language specification, coreLang mar file
langSpec = specification.load_language_specification_from_mar("mal_corelang_test.mar")

# Prints attacksteps for the assets RoutingFirewall
# attks = specification.get_attacks_for_class(langSpec,"RoutingFirewall")
# print(attks)

# Generate python classes from specification
pythClasses = classes_factory.LanguageClassesFactory(langSpec)
pythClasses.create_classes()

#Create a model object
honorModel = model.Model("honormodel", langSpec, pythClasses)

# Load model from json format
honorModel.load_from_file("honor_test.json")

# Save in a temp json file
# honorModel.save_to_file("tempModel.json")

# Generate attackgraps from model
attkgraph = attackgraph.AttackGraph()
attkgraph.generate_graph(langSpec, honorModel)
apriori.calculate_viability_and_necessity(attkgraph)
attkgraph.attach_attackers(honorModel)
# attkgraph.save_to_file("attackgraph_file.json")

# Create neo4j model instance
neo4j.ingest_model(honorModel, "neo4j://localhost:7687", "Fredrik",
"fred4551", "ingestmodel", delete=True)

# Create neo4j attackgraph instance
neo4j.ingest_attack_graph(attkgraph, "neo4j://localhost:7687", "Fredrik",
"fred4551", "attackgraphs", delete=True)
