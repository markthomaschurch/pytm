# Build the diagrams and reports of the threat models in the current
# directory. Installed in the pytm Docker image, whose entrypoint runs it in
# /work; it also works outside the image if the same tools are installed:
#
#   make -f docker/Makefile [TARGET...] [VARIABLE=value...]
#
# Run "make -f docker/Makefile help" for the targets and variables.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
.SUFFIXES:
MAKEFLAGS += --no-builtin-rules --warn-undefined-variables

# Models to build: every *_tm.py, or tm.py if there are none.
MODELS ?= $(or $(wildcard *_tm.py),$(wildcard tm.py))
# Each model is written to $(OUT)/<model>/ (tm.py -> ./tm/).
OUT ?= .
# Report formats built by "all" and "report".
FORMATS ?= md html pdf
# Report templates (pytm:<name> for one shipped with pytm, or a file). Each
# is written to <model>/<name>.md (.html, .pdf), named after the template
# (pytm:report.md.j2 -> report.md), with its thumbnails in thumbnails/<name>/.
REPORTS ?= pytm:report.md.j2
# Colour the DFD and its thumbnails by the severity of their findings.
COLORMAP ?= yes
# A theme directory with pandoc defaults files html.yaml and/or pdf.yaml.
THEME ?=
# PDF engine when the theme doesn't choose one (pandoc's default: pdflatex).
PDF_ENGINE ?=
# Extra options for pandoc, e.g. PANDOC_OPTS=--toc.
PANDOC_OPTS ?=

PYTHON ?= python3
DOT ?= dot
PLANTUML_PATH ?= /usr/local/lib/plantuml.jar
# Java takes user.home from /etc/passwd, which may have no entry for the
# user the image runs as.
PLANTUML ?= java -Djava.awt.headless=true -Duser.home=$(HOME) -jar $(PLANTUML_PATH)
PANDOC ?= pandoc

models := $(patsubst %.py,%,$(MODELS))
yes := $(filter yes true 1,$(COLORMAP))
colormap := $(if $(yes), --colormap)
theme := $(if $(THEME),$(abspath $(THEME)))
# pandoc options for the theme's defaults file $(1), if there is a theme.
theme_defaults = $(if $(theme),$(if $(wildcard $(theme)/$(1)),--defaults $(theme)/$(1),$(error THEME $(theme) has no $(1))))
# "$" in model text is not LaTeX math.
from := -f markdown-tex_math_dollars

# Output directory of model $(1) (its path without .py).
outdir = $(patsubst ./%,%,$(OUT)/$(notdir $(1)))
# Output name of report template $(1): pytm:report.md.j2 -> report.
report_name = $(basename $(basename $(notdir $(subst pytm:,,$(1)))))

.PHONY: all report dfd seq md html pdf clean help check
all: dfd seq report
report: $(FORMATS)

# $(1): the model's path without .py
define model_rules
$(call outdir,$(1))/dfd.png: $(1).py | $(call outdir,$(1))
	$$(PYTHON) $$< --dfd$$(colormap) | $$(DOT) -Tpng -o $$@

$(call outdir,$(1))/seq.png: $(1).py | $(call outdir,$(1))
	$$(PYTHON) $$< --seq | $$(PLANTUML) -tpng -pipe > $$@

$(call outdir,$(1)):
	mkdir -p $$@

dfd: $(call outdir,$(1))/dfd.png
seq: $(call outdir,$(1))/seq.png
endef

# $(1): the model's path without .py; $(2): a report template; $(3): the
# report's output path without extension; $(4): the report's name
define report_rules
# One run writes the report and the thumbnails (and legend images) it links.
$(3).md: $(1).py $(wildcard $(2)) $(call outdir,$(1))/dfd.png $(call outdir,$(1))/seq.png
	rm -rf $(call outdir,$(1))/thumbnails/$(4)
	$$(PYTHON) $$<$$(colormap) \
		--thumbnails $(call outdir,$(1))/thumbnails/$(4) --thumbnail-prefix thumbnails/$(4) \
		--report $(2) --report-var dfd_colormap=$$(if $$(yes),yes,no) > $$@

$(3).html: $(3).md
	cd $(call outdir,$(1)) && $$(PANDOC) $(4).md $$(from) \
		$$(or $$(call theme_defaults,html.yaml),--standalone --embed-resources) \
		$$(PANDOC_OPTS) -o $(4).html

$(3).pdf: $(3).md
	cd $(call outdir,$(1)) && $$(PANDOC) $(4).md $$(from) \
		$$(call theme_defaults,pdf.yaml) \
		$$(if $$(PDF_ENGINE),--pdf-engine=$$(PDF_ENGINE)) \
		$$(PANDOC_OPTS) -o $(4).pdf

md: $(3).md
html: $(3).html
pdf: $(3).pdf
endef

$(foreach m,$(models),$(eval $(call model_rules,$(m))))
$(foreach m,$(models),$(foreach r,$(REPORTS),$(eval $(call report_rules,$(m),$(r),$(call outdir,$(m))/$(call report_name,$(r)),$(call report_name,$(r))))))

check:
ifeq ($(strip $(models)),)
	$(error No models: no *_tm.py or tm.py here, and MODELS is not set)
endif
ifneq ($(words $(REPORTS)),$(words $(sort $(foreach r,$(REPORTS),$(call report_name,$(r))))))
	$(error Two templates in REPORTS have the same name: $(REPORTS))
endif

dfd seq md html pdf: check

clean:
	rm -rf $(foreach m,$(models),$(call outdir,$(m)))

help:
	@echo "Targets (default: all):"
	@echo "  all      diagrams, and every report in REPORTS in every format in FORMATS"
	@echo "  dfd      dataflow diagram       <model>/dfd.png"
	@echo "  seq      sequence diagram       <model>/seq.png"
	@echo "  report   every report in every format in FORMATS"
	@echo "  md       report Markdown        <model>/<report>.md (+ thumbnails/<report>/)"
	@echo "  html     report HTML            <model>/<report>.html"
	@echo "  pdf      report PDF             <model>/<report>.pdf"
	@echo "  clean    remove the models' output directories"
	@echo "Variables (VARIABLE=value):"
	@echo "  MODELS=a_tm.py b_tm.py  models to build (default: *_tm.py, or tm.py)"
	@echo "  OUT=dir        write each model to dir/<model>/ (default: .)"
	@echo "  FORMATS=...    report formats for all/report (default: md html pdf)"
	@echo "  REPORTS=...    report templates (default: pytm:report.md.j2); <report> is"
	@echo "                 the template's name, e.g. pytm:actions.md.j2 -> actions"
	@echo "  COLORMAP=no    don't colour the DFD by severity (default: yes)"
	@echo "  THEME=dir      pandoc theme: dir/html.yaml and dir/pdf.yaml"
	@echo "  PDF_ENGINE=... e.g. lualatex (default: the theme's, or pdflatex)"
	@echo "  PANDOC_OPTS=.. extra pandoc options"
	@echo "Models found: $(or $(MODELS),none)"
