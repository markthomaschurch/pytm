![build+test](https://github.com/OWASP/pytm/workflows/build%2Btest/badge.svg)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/11093/baseline)](https://www.bestpractices.dev/projects/11093)

# pytm: A Pythonic framework for threat modeling

![pytm logo](docs/pytm-logo.svg)

## Introduction

Traditional threat modeling too often comes late to the party, or sometimes not at all. In addition, creating manual data flows and reports can be extremely time-consuming. The goal of pytm is to shift threat modeling to the left, making threat modeling more automated and developer-centric.

## Features

Based on your input and definition of the architectural design, pytm can automatically generate the following items:
- Data Flow Diagram (DFD)
- Sequence Diagram
- Relevant threats to your system

## Requirements

* Linux/MacOS
* Python 3.11+
* Graphviz package
* Java (OpenJDK 10 or 11)
* [plantuml.jar](http://sourceforge.net/projects/plantuml/files/plantuml.jar/download)

## Installation

```
pip install pytm
```

A model is a Python script that imports pytm, so run it with the Python pytm is installed in (`python tm.py --dfd`), or with the `pytm` command that comes with the package:

```
pytm tm.py --dfd | dot -Tpng -o dfd.png
```

The `pytm` command also works when pytm is installed in its own environment, for example with [pipx](https://pipx.pypa.io/) (`pipx install pytm`), where a plain `python tm.py` could not import it. Options after the model are the model's own; see `pytm tm.py --help`.

Graphviz, PlantUML (with Java) and pandoc are separate tools; install them to render diagrams and reports.

## Getting Started

The `tm.py` is an example model. You can run it to generate the report and diagram image files that it references:

```
mkdir -p tm
./tm.py --report basic_template.md | pandoc -f markdown -t html > tm/report.html
./tm.py --dfd | dot -Tpng -o tm/dfd.png
./tm.py --seq | java -Djava.awt.headless=true -jar $PLANTUML_PATH -tpng -pipe > tm/seq.png
```

There's also an example `Makefile` that wraps all these into targets that can be easily shared for multiple models. If you have [GNU make](https://www.gnu.org/software/make/) installed (available by default on Linux distros but not on OSX), simply run:

```
make MODEL=the_name_of_your_model_minus_.py
```

You should either have plantuml.jar on the same directory as your model, or set PLANTUML_PATH.

### Getting Started - Docker Variant

To avoid installing the dependencies (Graphviz, Java and PlantUML, pandoc,
LaTeX), build the Docker image once and run it in the directory of your
models. It builds every `*_tm.py` there (or `tm.py` if there are none),
each into a directory of its own:

```bash
# do this once, in a pytm checkout
make image                       # or: docker build -t pytm .

# then, in your project, after every change to a model
docker run --rm -v "$PWD":/work pytm
```

For `payments_tm.py` this writes `payments_tm/`:

| File | Contents |
|---|---|
| `dfd.png` | dataflow diagram, coloured by the severity of each element's findings |
| `seq.png` | sequence diagram |
| `report.md` | the built-in report (`pytm:report.md.j2`) |
| `report.html` | the report as a single, self-contained HTML file |
| `report.pdf` | the report as a PDF |
| `thumbnails/report/` | the element thumbnails and legend images the report uses |

Files are only rebuilt when their model changes, and they are owned by the
owner of your project directory, not root. Arguments select what to build
and how:

```bash
docker run --rm -v "$PWD":/work pytm help              # targets and options
docker run --rm -v "$PWD":/work pytm dfd seq            # only the diagrams
docker run --rm -v "$PWD":/work pytm payments_tm.py     # only this model
docker run --rm -v "$PWD":/work pytm OUT=build FORMATS="md html"
docker run --rm -v "$PWD":/work pytm clean
```

| Option | Default | Meaning |
|---|---|---|
| `MODELS=a_tm.py b_tm.py` | `*_tm.py`, or `tm.py` | models to build (model files given as arguments are the same) |
| `OUT=dir` | `.` | write each model to `dir/<model>/` |
| `FORMATS=...` | `md html pdf` | report formats |
| `REPORTS=...` | `pytm:report.md.j2` | report templates (files in your project, or `pytm:<name>`), each written to `<model>/<name>.md`, `.html` and `.pdf` with its thumbnails in `thumbnails/<name>/`: `REPORTS="pytm:report.md.j2 pytm:actions.md.j2"` gives `report.*` and `actions.*` |
| `COLORMAP=no` | `yes` | don't colour the diagram by severity |
| `THEME=dir` | none | style the HTML and PDF with the pandoc defaults files `dir/html.yaml` and `dir/pdf.yaml` |
| `PDF_ENGINE=...` | the theme's, or `pdflatex` | e.g. `lualatex` |
| `PANDOC_OPTS=...` | none | extra pandoc options, e.g. `--toc` |

A theme outside your project has to be mounted too. Mount it at the same
path as on your computer, so that the paths inside its defaults files
work:

```bash
docker run --rm -v "$PWD":/work -v "$THEME:$THEME:ro" pytm THEME="$THEME"
```

The image's Makefile (`docker/Makefile`) also works without Docker, if the
same tools are installed: `make -f path/to/pytm/docker/Makefile`.

After changing the image, `docker/test-image.sh pytm` checks that it still
builds the example model's diagrams and reports, with and without a
LuaLaTeX theme; CI runs the same test.

### Getting Started - Devbox Variant

To simplify the usage of `pytm` host dependencies can be completely isolated
using [`Devbox`](https://github.com/jetify-com/devbox). This is usually a
lower overhead and more convenient alternative to the OCI container approach.

- Install Devbox on Linux/MacOS: `curl -fsSL https://get.jetify.com/devbox | bash`
- Install Devbox on [Windows/WSL](https://www.jetify.com/docs/devbox/installing-devbox/index#installing-wsl2)
- Update to latest version of devbox: `devbox version update`
- Set your GitHub access token in the `~/.config/nix/nix.conf` file: `access-tokens = github.com=YOUR_TOKEN_HERE`
- Create a new, isolated shell environment that includes all the tools and packages specified in the project's `devbox.json` file: `devbox shell`
- Display the full path to the Python executable that will be used when you simply type `python` in your terminal by using the which python command. The output should be the following path:  `.devbox/nix/profile/default/bin/python`
- Test by running the following command, which should generate a DFD as a PNG file called `sample.png`:  `./tm.py --dfd | dot -Tpng -o sample.png`
- Exit the Devbox shell environment: `exit`


### Getting Started - AI Variant

"But I thought we were done with this 'writing code' thing!" - this one is for those of us who are enjoying too much talking to AI assistants: check out https://github.com/izar/tm_skills for some ways to add OWASP pytm to your coding assistant (you'll still need to have a working install of pytm!).

## Usage

All available arguments:

```text
usage: tm.py [-h] [--debug] [--dfd] [--legend] [--report TEMPLATE]
             [--list-templates] [--report-var KEY=VALUE] [--exclude EXCLUDE]
             [--seq] [--list] [--colormap] [--describe DESCRIBE]
             [--list-elements] [--json JSON] [--thumbnails DIR]
             [--thumbnail-format {png,svg}] [--thumbnail-prefix PREFIX]
             [--levels LEVELS [LEVELS ...]] [--stale_days STALE_DAYS]

options:
  -h, --help            show this help message and exit
  --debug               print debug messages
  --dfd                 output DFD
  --legend              output a legend of the DFD's shapes (and, with
                        --colormap, colours) as a separate diagram
  --report TEMPLATE     output a report using TEMPLATE: a file (relative to
                        the current directory), or the name of a template
                        shipped with pytm, e.g. basic_template.md or
                        report.md.j2 (see --list-templates)
  --list-templates      list the report templates shipped with pytm
  --report-var KEY=VALUE
                        set a report template variable (repeatable), e.g.
                        --report-var dfd_image=dfd.png
  --exclude EXCLUDE     specify threat IDs to be ignored
  --seq                 output sequential diagram
  --list                list all available threats
  --colormap            color the DFD by the highest threat severity of each
                        element
  --describe DESCRIBE   describe the properties available for a given element
  --list-elements       list all elements which can be part of a threat model
  --json JSON           output a JSON file
  --thumbnails DIR      write a cropped DFD thumbnail for every element to DIR
                        (needs Graphviz; PNG also needs rsvg-convert)
  --thumbnail-format {png,svg}
                        thumbnail image format (default: png)
  --thumbnail-prefix PREFIX
                        path to the thumbnails as seen from the report, e.g.
                        'thumbnails' when the report is written next to DIR
                        (default: DIR)
  --levels LEVELS [LEVELS ...]
                        Select levels to be drawn in the threat model (int
                        separated by comma).
  --stale_days STALE_DAYS
                        checks if the delta between the TM script and the code
                        described by it is bigger than the specified value in
                        days
```

The *stale_days* argument tries to determine how far apart in days the model script (which you are writing) is from the code that implements the system being modeled. Ideally, they should be pretty close in most cases of an actively developed system. You can run this periodically to measure the pulse of your project and the 'freshness' of your threat model.

Currently available elements are: TM, Element, Server, ExternalEntity, Datastore, Actor, Process, Dataflow, Boundary, Lambda, LLM and Agent.

The available properties of an element can be listed by using `--describe` followed by the name of an element:

```text
$ ./tm.py --describe Server
Server class attributes:
  OS                        Operating system
                            default: ''
  assumptions               Assumptions about the element. These optionally allow to exclude threats with the given SIDs
                            default factory: list
  controls                  Security controls for this element
                            default factory: Controls
  data                      pytm.Data object(s) in incoming data flows
                            default factory: DataSet
  description               Description of the element
                            default: ''
  findings                  Threats that apply to this element
                            default factory: list
  handlesResources          Does this asset handle resources?
                            default: False
  inBoundary                Trust boundary this element exists in
                            default: None
  inScope                   Is the element in scope of the threat model
                            default: True
  inputs                    incoming Dataflows
                            default factory: list
  levels                    List of levels (0, 1, 2, ...) to be drawn in the model
                            default factory: <lambda>
  maxClassification         Maximum data classification this element can handle
                            default: <Classification.UNKNOWN: 0>
  minTLSVersion             Minimum TLS version required
                            default: <TLSVersion.NONE: 0>
  name                      Name of the element
                            required
  onAWS                     Is this asset on AWS?
                            default: False
  outputs                   outgoing Dataflows
                            default factory: list
  overrides                 Overrides to findings, allowing to set a custom response, CVSS score or override other attributes
                            default factory: list
  port                      Default TCP port for incoming data flows
                            default: -1
  protocol                  Default network protocol for incoming data flows
                            default: ''
  severity                  Severity level of threats affecting this element
                            default: 0
  sourceFiles               Location of the source code that describes this element relative to the directory of the model script
                            default factory: list
  usesCache                 Does this server use cache?
                            default: False
  usesEnvironmentVariables  Does this asset use environment variables?
                            default: False
  usesSessionTokens         Does this server use session tokens?
                            default: False
  usesVPN                   Does this server use VPN?
                            default: False
  usesXMLParser             Does this server use XML parser?
                            default: False
  uuid                      default factory: <lambda>

```

Use `python tm.py --describe Controls` to list security control properties, their descriptions, and their defaults.

The *colormap* argument, used together with *dfd*, outputs a color-coded DFD where each element and dataflow is colored by the highest severity of the threats found against it: red for Very High, orange for High, gold for Medium, and green for Low, Very Low or Info. Elements no threat applies to are drawn in grey without a fill. The colors show threat severity only; they don't take likelihood into account, so they are not a risk rating. Boundaries are drawn in black so they don't compete with the colors.


## Usage - Devbox Variant

- `devbox shell`
- `pytm` usage as usual
- `exit`

## Creating a Threat Model

The following is a sample `tm.py` file that describes a simple application where a User logs into the application
and posts comments on the app. The app server stores those comments into the database. There is an AWS Lambda
that periodically cleans the Database.

```python

#!/usr/bin/env python3

from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Lambda, LLM, Data, Classification, DatastoreType


tm = TM("my test tm")
tm.description = "another test tm"
tm.isOrdered = True

User_Web = Boundary("User/Web")
Web_DB = Boundary("Web/DB")

user = Actor("User")
user.inBoundary = User_Web

web = Server("Web Server")
web.OS = "CloudOS"
web.controls.isHardened = True
web.sourceFiles = ["server/web.cc"]

db = Datastore("SQL Database (*)")
db.OS = "CentOS"
db.controls.isHardened = False
db.inBoundary = Web_DB
db.type = DatastoreType.SQL
db.inScope = False
db.sourceFiles = ["model/schema.sql"]

comments = Data(
    name="Comments", 
    description="Comments in HTML or Markdown",  
    classification=Classification.PUBLIC,  
    isPII=False,
    isCredentials=False,  
    # credentialsLife=Lifetime.LONG,  
    isStored=True, 
    isSourceEncryptedAtRest=False, 
    isDestEncryptedAtRest=True 
)

results = Data(
    name="results", 
    description="Results of insert op",  
    classification=Classification.SENSITIVE,  
    isPII=False, 
    isCredentials=False,  
    # credentialsLife=Lifetime.LONG,  
    isStored=True, 
    isSourceEncryptedAtRest=False, 
    isDestEncryptedAtRest=True 
)

my_lambda = Lambda("cleanDBevery6hours")
my_lambda.controls.hasAccessControl = True
my_lambda.inBoundary = Web_DB

llm_api = LLM("AI Writing Assistant")
llm_api.isThirdParty = True
llm_api.processesPersonalData = True
llm_api.hasContentFiltering = False
llm_api.hasSystemPrompt = True
llm_api.processesUntrustedInput = True

my_lambda_to_db = Dataflow(my_lambda, db, "(&lambda;)Periodically cleans DB")
my_lambda_to_db.protocol = "SQL"
my_lambda_to_db.dstPort = 3306

user_to_web = Dataflow(user, web, "User enters comments (*)")
user_to_web.protocol = "HTTP"
user_to_web.dstPort = 80
user_to_web.data = comments

web_to_user = Dataflow(web, user, "Comments saved (*)")
web_to_user.protocol = "HTTP"

web_to_db = Dataflow(web, db, "Insert query with comments")
web_to_db.protocol = "MySQL"
web_to_db.dstPort = 3306

db_to_web = Dataflow(db, web, "Comments contents")
db_to_web.protocol = "MySQL"
db_to_web.data = results

web_to_llm = Dataflow(web, llm_api, "Chat completion request")
web_to_llm.protocol = "HTTPS"
web_to_llm.dstPort = 443

tm.process()

```

You also have the option of using [pytmGPT](https://chat.openai.com/g/g-soISG24ix-pytmgpt) to create your models from prose!

### Assumptions

An `Assumption` records a claim about the system, for the whole model (`tm.assumptions`) or one element (`element.assumptions`). One that lists threat SIDs in `exclude` suppresses those threats: their findings are moved to `tm.excluded_findings` instead of `tm.findings`.

Assumptions often need someone to confirm them. Record who is responsible with `verifier`, and once it is confirmed, `verified=True` and `verifiedOn` (an ISO date):

```python
web.assumptions = [
    Assumption(
        "No PHP on the web server",
        exclude=["INP16"],
        verifier="Platform team",
        verified=True,
        verifiedOn="2026-11-01",
    ),
    Assumption("Patched weekly", exclude=["SC02"], verifier="Ana Smith"),
]
```

By default every assumption suppresses the threats it excludes. With `tm.requireVerifiedAssumptions = True`, only verified ones do: the findings of an unverified assumption stay findings until it is verified.

### Generating Diagrams

Diagrams are output as [Dot](https://graphviz.gitlab.io/) and [PlantUML](https://plantuml.com/).

When `--dfd` argument is passed to the above `tm.py` file it generates output to stdout, which is fed to Graphviz's dot to generate the Data Flow Diagram:

```bash

tm.py --dfd | dot -Tpng -o sample.png

```

Generates this diagram:

![dfd.png](docs/diagrams/dfd.png)

`tm.py --legend` outputs a legend for the DFD as a separate diagram: a sample of each shape the model uses and, with `--colormap`, what each colour means (`tm.py --legend --colormap | dot -Tpng -o legend.png`). The legend is drawn by the same code as the DFD, so it always matches it.

Adding ".levels = [1,2]" attributes to an element will cause it (and its associated Dataflows if both flow endings are in the same DFD level) to render (or not) depending on the command argument "--levels 1 2".

The following command generates a Sequence diagram.

```bash

tm.py --seq | java -Djava.awt.headless=true -jar plantuml.jar -tpng -pipe > seq.png

```

Generates this diagram:

![seq.png](docs/diagrams/seq.png)

### Creating a Report

The diagrams and findings can be included in the template to create a final report:

```bash

tm.py --report basic_template.md | pandoc -f markdown -t html > report.html

```

`--report` takes a template file, or the name of a template that ships with pytm: it looks for the file relative to the current directory first, and otherwise uses the packaged template of that name. `--list-templates` shows the packaged ones (`basic_template.md`, `advanced_template.md`, and the Jinja2 `report.md.j2`). To customize one, copy it next to your model under the same name, and your copy is used instead. `pytm:NAME` always selects the packaged template. Earlier paths such as `docs/basic_template.md` still work.

The packaged templates link `Stylesheet.css` through a `{stylesheet}` variable. It is found the same way, so a `Stylesheet.css` in the current directory is used instead of the packaged one, and `--report-var stylesheet=PATH` sets it directly. The link is a `file://` URI by default; add `--embed-resources` when converting with pandoc (`pandoc report.md -s --embed-resources -o report.html`) to put the styles inside the HTML file.

The templating format used in the report template is very simple:

```text

# Threat Model Sample
***

## System Description

{tm.description}

## Dataflow Diagram

![Level 0 DFD](dfd.png)

## Dataflows

Name|From|To |Data|Protocol|Port
----|----|---|----|--------|----
{dataflows:repeat:{{item.name}}|{{item.source.name}}|{{item.sink.name}}|{{item.data}}|{{item.protocol}}|{{item.dstPort}}
}

## Findings

{findings:repeat:* {{item.description}} on element "{{item.target}}"
}

```

To group findings by elements, use a more advanced, nested loop:

```text
## Findings

{elements:repeat:{{item.findings:if:
### {{item.name}}

{{item.findings:repeat:
**Threat**: {{{{item.id}}}} - {{{{item.description}}}}

**Severity**: {{{{item.severity}}}}

**Mitigations**: {{{{item.mitigations}}}}

**References**: {{{{item.references}}}}

}}}}}
```

All items inside a loop must be escaped, doubling the braces, so `{item.name}` becomes `{{item.name}}`.
The example above uses two nested loops, so items in the inner loop must be escaped twice, that's why they're using four braces.

#### Linking between sections

`getAnchor` returns a stable, unique identifier for an element, dataflow, boundary, piece of data, threat or finding, such as `server-web-server`, `dataflow-login` or `threat-inp01`. Elements with the same type and name are numbered in the order they were created (`server-web-server-2`). Use it for pandoc heading IDs and links:

```text
{assets:repeat:### {{item.name}} {{{{#{{item:call:getAnchor}}}}}}

}
{dataflows:repeat:* [{{item.name}}](#{{item:call:getAnchor}}) from [{{item.source.name}}](#{{item.source:call:getAnchor}})
}
```

Literal braces inside a loop are doubled like any other, so the pandoc heading attribute `{#...}` is written `{{{{#...}}}}` in the loop above.

`getThreatAnchor` returns the anchor of the threat behind a finding, for linking a finding to its threat's details.

#### Built-in report

pytm ships a complete, cross-linked report template (it needs Jinja2: `pip install 'pytm[jinja]'`). Select it with `pytm:report.md.j2`:

```bash
./tm.py --dfd | dot -Tpng -o report/dfd.png
./tm.py --seq | java -Djava.awt.headless=true -jar $PLANTUML_PATH -tpng -pipe > report/seq.png
./tm.py --thumbnails report/thumbnails --thumbnail-prefix thumbnails \
        --report pytm:report.md.j2 > report/report.md
cd report && pandoc report.md -s --embed-resources -o report.html && pandoc report.md -o report.pdf
```

It contains a summary; the dataflow and sequence diagrams; a data dictionary (each piece of data with the elements that handle it, the dataflows that carry it and the threats against them); sections for actors, dataflows, assets and trust boundaries (details, controls in place, attached dataflows, data, findings and thumbnails); every finding with how to resolve it (the specific values to change, e.g. "set `controls.sanitizesInput` to `True`", with alternatives when there are several ways; alternatives that only add safeguards come first, and changes that merely describe the system differently, such as `isResponse` or `inScope`, are marked); the model's assumptions (each with whether and by whom it was verified, the findings it suppressed or would suppress once verified, flagging excluded threat IDs that suppressed nothing or aren't in the threat library) and the threats left out with `--exclude`; an assumption verification section listing the unverified assumptions by who is responsible for verifying them, and the verified ones with who verified them and when; each element's own assumptions and the threats suppressed on it; every suppressed finding with the assumption behind it, so reviewers can check that each assumption still holds; and a threat library limited to the threats that apply to the model (suppressed ones included), with each condition laid out over short lines and one reference per line. Every element, finding, assumption and threat links to the others.

The diagrams default to `dfd.png` and `seq.png` next to the report; change them with `--report-var dfd_image=PATH` and `--report-var seq_image=PATH`, or set one to an empty value to leave it out. A legend table follows the DFD; if `dfd.png` was rendered with `--colormap`, add `--report-var dfd_colormap=yes` to explain its colours too. When thumbnails are rendered (`--thumbnails`), the same step draws each legend shape and colour as a small image, and the legend table shows those instead of their names. The report starts with a small pandoc metadata block that makes links visible in PDF output (`colorlinks`) and sets the HTML page title; leave it out with `--report-var pandoc_metadata=no`. The links use pandoc's heading IDs (`{#...}`), so they work in pandoc's HTML and PDF output but not in Markdown previews (such as GitHub's) that don't support heading attributes.

The report is built from sub-templates (`pytm/templates/sections/*.md.j2`) and shared macros (`pytm/templates/_macros.md.j2`). To customize one part, copy `report.md.j2` next to your model, and add a file with the same name as the section you want to change (for example `sections/threats.md.j2`): templates next to your template are used before the built-in ones.

#### Action report

`pytm:actions.md.j2` is a shorter report of only what needs doing, rendered the same way (`--report pytm:actions.md.j2`, with the same `--report-var` variables). After the diagrams it lists:

- **Threats by severity:** every finding, Very High first, with its target, mitigations and how to resolve it, and a note when an unverified assumption would suppress it once verified.
- **Assumptions to verify:** the unverified assumptions that would suppress findings once verified (with `tm.requireVerifiedAssumptions`), ordered by the combined severity of those findings (Very High counts 5, High 4, Medium 3, Low 2, Very Low 1), each with who is responsible and the findings it would suppress.
- **Assumptions to verify, by person:** each verifier's list, then those no one is assigned.

Everything else is left out: suppressed findings, verified assumptions, assumptions that affect no finding, and the element, data and threat library sections (links that would point at them, such as a finding's target, are shown as plain text).

#### Jinja2 templates

Templates whose name ends in `.j2` or `.jinja` (for example `report.md.j2`) are rendered with [Jinja2](https://jinja.palletsprojects.com/) instead. Install it with `pip install 'pytm[jinja]'`. Jinja2 templates get the same variables (`tm`, `elements`, `assets`, `actors`, `boundaries`, `dataflows`, `data`, `threats`, `findings`) plus:

- functions: `anchor(obj)`, `heading_id(obj)`, `link(obj, text=None)`, `threat_anchor(finding)`, `thumbnail(obj)`
- filters: `md_escape`, `slugify`, `anchor`, and every helper above, e.g. `{{ asset | getFindingCount }}`

```jinja
{% for asset in assets %}
## {{ asset.name | md_escape }} {{ heading_id(asset) }}

{% if thumbnail(asset) %}![{{ asset.name | md_escape }}]({{ thumbnail(asset) }}){% endif %}

Findings: {{ asset | getFindingCount }}
{% endfor %}
```

Pandoc's heading ID syntax `{#...}` starts a comment in Jinja2, so use `heading_id(obj)` (or pandoc's spaced form `{ #... }`). `{% include %}` finds templates next to the main template, and using an undefined variable is an error rather than empty output.

#### Cross-references

These helpers link the parts of a model together. In format-string templates call them with `:call:` (for example `{{item:call:getFlows:...}}`); in Jinja2 templates use the function names in brackets.

| Helper | Returns |
|---|---|
| `getFlows`, `getInboundFlows`, `getOutboundFlows` (`flows_of(el, direction=None)`) | dataflows attached to an element |
| `getData` (`data_of(el)`) | data an element produces or consumes, or a dataflow carries |
| `getDataHandlers` (`handlers_of(data)`) | elements that send, receive, store or process the data |
| `getDataCarriers` (`carriers_of(data)`) | dataflows that carry the data |
| `getDataFindings` (`data_findings_of(data)`) | findings against the dataflows that carry the data |
| `getBoundaryMembers` (`members_of(boundary)`) | elements and boundaries directly inside a boundary |
| `getElementFindings`, `getElementThreats` (`findings_of(el)`, `threats_of(el)`) | findings against an element, and the distinct threats behind them |
| `getFiredThreats` (`fired_threats()`) | every threat with at least one finding, for a threat library |
| `getThreatFindings` (`findings_for(threat)`) | the findings a threat produced |
| (Jinja2 only) `assumptions_of(el=None)` | assumptions about an element, or about the whole model: each with `name`, `description`, `exclude`, `anchor`, the findings it `suppressed`, and the excluded threat IDs that suppressed nothing (`unused`) or aren't in the threat library (`unknown`) |
| (Jinja2 only) `suppressed_of(el=None)`, `suppressed_for(threat)`, `data_suppressed_of(data)`, `assumption_of(finding)` | findings an assumption suppressed (all, on an element, of a threat, or on the dataflows that carry the data), and the assumption that suppressed one |
| (Jinja2 only) `all_assumptions()`, `pending_assumptions_of(finding)`, `requires_verified_assumptions()` | every assumption (model's, then each element's), with `verified`, `verifier`, `verifiedOn` and, when the model requires verified assumptions, the findings it would suppress once verified (`pending`); the unverified assumptions that would suppress a finding; and whether `tm.requireVerifiedAssumptions` is set |
| (Jinja2 only) `assumptions_by_risk()`, `findings_by_severity(findings)` | unverified assumptions that would suppress findings once verified, the most at stake first (each with `pending`, `risk` and `risk_counts()`); findings grouped by severity as `(severity, findings)` pairs, most severe first |
| (Jinja2 only) `reported_threats()` | threats with a finding or a suppressed finding, for a threat library |
| (Jinja2 only) `excluded_threats()` | threats left out with `--exclude`, as `(id, threat)` pairs (`threat` is `None` for an unknown id) |
| `getFindingRemedies` (`remedies_of(finding)`) | how to resolve a finding: alternative sets of changes, each with `attribute`, `required`, `current`, `subject` and a readable `instruction`; making every change in any one set makes the threat stop applying |

For example, how to resolve each finding:

```jinja
{% for finding in findings %}

### {{ finding.threat_id }} on {{ finding.target }}

{% for changes in remedies_of(finding) %}
{{ loop.index }}. {% for c in changes %}{{ c.instruction }}{{ " and " if not loop.last }}{% endfor %}

{% endfor %}
{% endfor %}
```

#### Element thumbnails

`--thumbnails DIR` writes a small image for every element, dataflow, boundary and piece of data: the DFD with that object highlighted in blue, cropped to it and the elements directly connected to it. Unrelated elements inside the crop are faded. Files are named after the object's anchor (`DIR/server-web-server.png`). Thumbnails follow `--colormap` and `--levels`, and need Graphviz's `dot`; PNG (the default) also needs `rsvg-convert` (`librsvg2-bin` on Debian/Ubuntu). Use `--thumbnail-format svg` for SVG.

In a template, `getThumbnailMarkdown` returns a Markdown image of an element's thumbnail (or nothing, if it has none) and `getThumbnail` returns just the link. `--thumbnail-prefix` sets how the report refers to `DIR`, so links work when the report is written somewhere else:

```bash
./tm.py --thumbnails report/thumbnails --thumbnail-prefix thumbnails \
        --report basic_template.md > report/report.md
```

```text
{assets:repeat:### {{item.name}} {{{{#{{item:call:getAnchor}}}}}}

{{item:call:getThumbnailMarkdown}}

}
```

### Overrides

You can override attributes of findings (threats matching the model assets and/or dataflows), for example to set a custom CVSS score and/or response text:

```python
user_to_web = Dataflow(user, web, "User enters comments (*)", protocol="HTTP", dstPort="80")
user_to_web.overrides = [
    Finding(
        # Overflow Buffers
        threat_id="INP02",
        cvss="9.3",
        response="""**To Mitigate**: run a memory sanitizer to validate the binary""",
        severity="Very High",
    )
]
```

If you are adding a Finding, make sure to add a severity: "Very High", "High", "Medium", "Low", "Very Low".

## Threats database

For the security practitioner, you may supply your own threats file by setting `TM.threatsFile`. It should contain entries like:

```json
{
   "SID":"INP01",
   "target": ["Lambda","Process"],
   "description": "Buffer Overflow via Environment Variables",
   "details": "This attack pattern involves causing a buffer overflow through manipulation of environment variables. Once the attacker finds that they can modify an environment variable, they may try to overflow associated buffers. This attack leverages implicit trust often placed in environment variables.",
   "Likelihood Of Attack": "High",
   "severity": "High",
   "condition": "target.usesEnvironmentVariables is True and target.controls.sanitizesInput is False and target.controls.checksInputBounds is False",
   "prerequisites": "The application uses environment variables.An environment variable exposed to the user is vulnerable to a buffer overflow.The vulnerable environment variable uses untrusted data.Tainted data used in the environment variables is not properly validated. For instance boundary checking is not done before copying the input data to a buffer.",
   "mitigations": "Do not expose environment variable to the user.Do not use untrusted data in your environment variables. Use a language or compiler that performs automatic bounds checking. There are tools such as Sharefuzz [R.10.3] which is an environment variable fuzzer for Unix that support loading a shared library. You can use Sharefuzz to determine if you are exposing an environment variable vulnerable to buffer overflow.",
   "example": "Attack Example: Buffer Overflow in $HOME A buffer overflow in sccw allows local users to gain root access via the $HOME environmental variable. Attack Example: Buffer Overflow in TERM A buffer overflow in the rlogin program involves its consumption of the TERM environmental variable.",
   "references": "https://capec.mitre.org/data/definitions/10.html, CVE-1999-0906, CVE-1999-0046, http://cwe.mitre.org/data/definitions/120.html, http://cwe.mitre.org/data/definitions/119.html, http://cwe.mitre.org/data/definitions/680.html"
 }
```

To keep pytm's threat library and add threats of your own, list your files in `TM.extraThreatsFiles` instead; they are loaded after `TM.threatsFile`, in order:

```python
tm = TM("my tm")
tm.extraThreatsFiles = ["project_threats.json"]
```

A relative path is looked up next to the model script first, then in the current directory, so the model finds its files wherever it is run from. Each threat `SID` may appear only once across all the files: a duplicate is an error that names both files. Setting either attribute reloads the threats.

The `target` field lists classes of model elements to match this threat against.
Those can be assets, like: Actor, Datastore, Server, Process, ExternalEntity,
Lambda, LLM, Agent or Element, which is the base class and matches any. It can also be a Dataflow that connects two assets.

All other fields (except `condition`) are available for display and can be used in the template
to list findings in the final [report](#report).

> **WARNING**
>
> The `threats.json` file contains strings that run through `eval()`. Make sure the file has correct permissions
> or risk having an attacker change the strings and cause you to run code on their behalf.

The logic lives in the `condition`, where members of `target` can be logically evaluated.
Returning a true means the rule generates a finding, otherwise, it is not a finding.
Condition may compare attributes of `target` and/or control attributes of the 'target.control' and also call one of these methods:

For the meaning of commonly used model properties and controls, including
`checksInputBounds` and `sourceFiles`, see [Model properties and threat conditions](docs/model-properties.md).

* `target.oneOf(class, ...)` where `class` is one or more: Actor, Datastore, Server, Process, ExternalEntity, Lambda, LLM, Agent or Dataflow,
* `target.crosses(Boundary)`,
* `target.enters(Boundary)`,
* `target.exits(Boundary)`,
* `target.inside(Boundary)`.

If `target` is a Dataflow, remember you can access `target.source` and/or `target.sink` along with other attributes.

Conditions on assets can analyze all incoming and outgoing Dataflows by inspecting
the `target.input` and `target.output` attributes. For example, to match a threat only against
servers with incoming traffic, use `any(target.inputs)`. A more advanced example,
matching elements connecting to SQL datastores, would be `any(f.sink.oneOf(Datastore) and f.sink.type == DatastoreType.SQL for f in target.outputs)`.

## Importing from JSON

With a little bit of Python code it is possible to import a threat model from JSON (notice the special format in the example found in `tests/input.json`). The following example imports the `input.json` example found in tests. Save the following code as `tm2.py`.

```python

#!/usr/bin/env python3
# Example tm2.py contents
# Run: python tm2.py --dfd | dot -Tpng -o sample_json.png

from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    Lambda,
    Server,
    DatastoreType,
    Assumption,
    load,
)

json_file_string = './tests/input.json'
with open(json_file_string) as input_json:
    TM.reset()
    tm = load(input_json)
    tm.process()

```

We can call `tm2.py` the same way as we did before, here with `--dfd` and then redirect the output to Graphviz (`dot`): 

```bash

python tm2.py --dfd | dot -Tpng -o sample_json.png

```

## Making slides!

Once a threat model is done and ready, the dreaded presentation stage comes in - and now pytm can help you there as well, with a template that expresses your threat model in slides, using the power of [RevealMD](https://github.com/webpro/reveal-md)! Just use the template docs/reveal.md and you will get some pretty slides, fully configurable, that you can present and share from your browser.



https://github.com/OWASP/pytm/assets/368769/30218241-c7cc-4085-91e9-bbec2843f838



## Currently supported threats

```text
INP01 - Buffer Overflow via Environment Variables
INP02 - Overflow Buffers
INP03 - Server Side Include (SSI) Injection
CR01 - Session Sidejacking
INP04 - HTTP Request Splitting
CR02 - Cross Site Tracing
INP05 - Command Line Execution through SQL Injection
INP06 - SQL Injection through SOAP Parameter Tampering
SC01 - JSON Hijacking (aka JavaScript Hijacking)
LB01 - API Manipulation
AA01 - Authentication Abuse/ByPass
DS01 - Excavation
DE01 - Interception
DE02 - Double Encoding
API01 - Exploit Test APIs
AC01 - Privilege Abuse
INP07 - Buffer Manipulation
AC02 - Shared Data Manipulation
DO01 - Flooding
HA01 - Path Traversal
AC03 - Subverting Environment Variable Values
DO02 - Excessive Allocation
DS02 - Try All Common Switches
INP08 - Format String Injection
INP09 - LDAP Injection
INP10 - Parameter Injection
INP11 - Relative Path Traversal
INP12 - Client-side Injection-induced Buffer Overflow
AC04 - XML Schema Poisoning
DO03 - XML Ping of the Death
AC05 - Content Spoofing
INP13 - Command Delimiters
INP14 - Input Data Manipulation
DE03 - Sniffing Attacks
CR03 - Dictionary-based Password Attack
API02 - Exploit Script-Based APIs
HA02 - White Box Reverse Engineering
DS03 - Footprinting
AC06 - Using Malicious Files
HA03 - Web Application Fingerprinting
SC02 - XSS Targeting Non-Script Elements
AC07 - Exploiting Incorrectly Configured Access Control Security Levels
INP15 - IMAP/SMTP Command Injection
HA04 - Reverse Engineering
SC03 - Embedding Scripts within Scripts
INP16 - PHP Remote File Inclusion
AA02 - Principal Spoof
CR04 - Session Credential Falsification through Forging
DO04 - XML Entity Expansion
DS04 - XSS Targeting Error Pages
SC04 - XSS Using Alternate Syntax
CR05 - Encryption Brute Forcing
AC08 - Manipulate Registry Information
DS05 - Lifting Sensitive Data Embedded in Cache
SC05 - Removing Important Client Functionality
INP17 - XSS Using MIME Type Mismatch
AA03 - Exploitation of Trusted Credentials
AC09 - Functionality Misuse
INP18 - Fuzzing and observing application log data/errors for application mapping
CR06 - Communication Channel Manipulation
AC10 - Exploiting Incorrectly Configured SSL
CR07 - XML Routing Detour Attacks
AA04 - Exploiting Trust in Client
CR08 - Client-Server Protocol Manipulation
INP19 - XML External Entities Blowup
INP20 - iFrame Overlay
AC11 - Session Credential Falsification through Manipulation
INP21 - DTD Injection
INP22 - XML Attribute Blowup
INP23 - File Content Injection
DO05 - XML Nested Payloads
AC12 - Privilege Escalation
AC13 - Hijacking a privileged process
AC14 - Catching exception throw/signal from privileged block
INP24 - Filter Failure through Buffer Overflow
INP25 - Resource Injection
INP26 - Code Injection
INP27 - XSS Targeting HTML Attributes
INP28 - XSS Targeting URI Placeholders
INP29 - XSS Using Doubled Characters
INP30 - XSS Using Invalid Characters
INP31 - Command Injection
INP32 - XML Injection
INP33 - Remote Code Inclusion
INP34 - SOAP Array Overflow
INP35 - Leverage Alternate Encoding
DE04 - Audit Log Manipulation
AC15 - Schema Poisoning
INP36 - HTTP Response Smuggling
INP37 - HTTP Request Smuggling
INP38 - DOM-Based XSS
AC16 - Session Credential Falsification through Prediction
INP39 - Reflected XSS
INP40 - Stored XSS
AC17 - Session Hijacking - ServerSide
AC18 - Session Hijacking - ClientSide
INP41 - Argument Injection
AC19 - Reusing Session IDs (aka Session Replay) - ServerSide
AC20 - Reusing Session IDs (aka Session Replay) - ClientSide
AC21 - Cross Site Request Forgery
DS06 - Data Leak
DR01 - Unprotected Sensitive Data
AC22 - Credentials Aging (deprecated)
AC23 - Credentials Disclosure
AC24 - Use of hardcoded credentials
LLM01 - Direct Prompt Injection
LLM02 - Indirect Prompt Injection via Retrieved Content
LLM03 - Sensitive Data Leakage to Third-Party Provider
LLM04 - Training Data Poisoning
LLM05 - Excessive Agency via Unauthorized Tool Use
LLM06 - Arbitrary Code Execution via LLM Agent
LLM07 - Jailbreaking and Safety Bypass
LLM08 - Sensitive Information Disclosure Through Output
LLM09 - Untrusted Tool Launch Configuration


```
