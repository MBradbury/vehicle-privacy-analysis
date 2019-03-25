#!/usr/bin/env python3

from collections import defaultdict
from enum import Enum, IntFlag

class Threat(Enum):
	DirectAccess = 0
	VisualIdentification = 1
	InternalVehicleCommunication = 2
	ExternalVehicleCommunication = 3
	NonvehicleCommunication = 4
	Behavioural = 5
	Services = 6
	Historical = 7

	@property
	def letter(self):
		return {
			Threat.DirectAccess: "A",
			Threat.VisualIdentification: "B",
			Threat.InternalVehicleCommunication: "D",
			Threat.ExternalVehicleCommunication: "E",
			Threat.NonvehicleCommunication: "F",
			Threat.Behavioural: "G",
			Threat.Services: "C",
			Threat.Historical: "H",
		}[self]

	@property
	def label(self):
		return {
			Threat.DirectAccess: "Direct Access",
			Threat.VisualIdentification: "Visual Identification",
			Threat.InternalVehicleCommunication: "Internal Vehicle Communication",
			Threat.ExternalVehicleCommunication: "External Vehicle Communication",
			Threat.NonvehicleCommunication: "Non-vehicle Communication",
			Threat.Behavioural: "Behavioural",
			Threat.Services: "Services",
			Threat.Historical: "Historical",
		}[self]

class Technique(IntFlag):
	No = 0
	JamSignal = 1
	PerturbIdentity = 2
	PerturbContents = 4
	ChangeCommunicationPatterns = 8
	ChangeBehaviouralPatterns = 16

	@property
	def letter(self):
		return {
			Technique.JamSignal: "A",
			Technique.PerturbIdentity: "B",
			Technique.PerturbContents: "C",
			Technique.ChangeCommunicationPatterns: "D",
			Technique.ChangeBehaviouralPatterns: "E",
		}[self]

	@property
	def label(self):
		return {
			Technique.JamSignal: "Jam Signals",
			Technique.PerturbIdentity: "Perturb Identity",
			Technique.PerturbContents: "Perturb Data",
			Technique.ChangeCommunicationPatterns: "Change Communication Patterns",
			Technique.ChangeBehaviouralPatterns: "Change Behavioural Patterns",
		}[self]

threat_technique_mappings = {
	Threat.DirectAccess: Technique.JamSignal,
	Threat.VisualIdentification: Technique.PerturbIdentity | Technique.ChangeBehaviouralPatterns,
	Threat.InternalVehicleCommunication: Technique.PerturbIdentity | Technique.PerturbContents | Technique.ChangeCommunicationPatterns,
	Threat.ExternalVehicleCommunication: Technique.PerturbIdentity | Technique.PerturbContents | Technique.ChangeCommunicationPatterns,
	Threat.NonvehicleCommunication: Technique.PerturbIdentity | Technique.PerturbContents | Technique.ChangeCommunicationPatterns,
	Threat.Behavioural: Technique.ChangeBehaviouralPatterns,
	Threat.Services: Technique.PerturbIdentity | Technique.PerturbContents | Technique.ChangeBehaviouralPatterns,
	Threat.Historical: Technique.PerturbContents,
}

threats = {
	"Physically Attached Sensor": Threat.DirectAccess,
	"Fleet Mgmt and Black Box": Threat.DirectAccess,
	"Smartphone GNSS Sensor": Threat.DirectAccess,
	"ANPR": Threat.VisualIdentification,
	"Visual Tracking": Threat.VisualIdentification,
	"Location Based Services": Threat.Services,
	"CAN Bus Access": Threat.InternalVehicleCommunication,
	"Vehicular Sensor Network": Threat.InternalVehicleCommunication,
	"PRKE": Threat.InternalVehicleCommunication,
	"Signal Direction Context": Threat.InternalVehicleCommunication, # Or External
	"Eavesdrop TDMA MAC Slots": Threat.ExternalVehicleCommunication,
	"Eavesdrop V2X": Threat.ExternalVehicleCommunication,
	"Cell Tower Localisation": Threat.NonvehicleCommunication,
	"ISMI Catchers": Threat.NonvehicleCommunication,
	"Eavesdrop Bluetooth": Threat.NonvehicleCommunication,
	"Eavesdrop WiFI": Threat.NonvehicleCommunication,
	"Driving Style and Behaviour": Threat.Behavioural,
	"Smartphone Permissionless Sensors": Threat.Behavioural,
	"Database Leak": Threat.Historical,
}

techniques = {
	"Physically Attached Sensor": Technique.JamSignal,
	"Fleet Mgmt and Black Box": Technique.JamSignal,
	"Smartphone GNSS Sensor": Technique.JamSignal,
	"ANPR": Technique.PerturbIdentity | Technique.ChangeBehaviouralPatterns,
	"Visual Tracking": Technique.ChangeBehaviouralPatterns,
	"Location Based Services": Technique.PerturbIdentity | Technique.PerturbContents,
	"CAN Bus Access": Technique.No,
	"Vehicular Sensor Network": Technique.PerturbIdentity,
	"PRKE": Technique.PerturbIdentity | Technique.ChangeCommunicationPatterns,
	"Signal Direction Context": Technique.ChangeCommunicationPatterns,
	"Eavesdrop TDMA MAC Slots": Technique.PerturbIdentity | Technique.ChangeCommunicationPatterns,
	"Eavesdrop V2X": Technique.PerturbIdentity | Technique.ChangeCommunicationPatterns,
	"Cell Tower Localisation": Technique.ChangeCommunicationPatterns,
	"ISMI Catchers": Technique.No,
	"Eavesdrop Bluetooth": Technique.PerturbIdentity | Technique.ChangeCommunicationPatterns,
	"Eavesdrop WiFI": Technique.PerturbIdentity | Technique.ChangeCommunicationPatterns,
	"Driving Style and Behaviour": Technique.ChangeBehaviouralPatterns,
	"Smartphone Permissionless Sensors": Technique.ChangeBehaviouralPatterns,
	"Database Leak": Technique.PerturbContents,
}

output_order = list(enumerate([
	"Physically Attached Sensor",
	"Fleet Mgmt and Black Box",
	"Smartphone GNSS Sensor", # Permissions
	"ANPR",
	"Visual Tracking",
	"Location Based Services",
	"CAN Bus Access",
	"Vehicular Sensor Network",
	"PRKE",
	"Signal Direction Context",
	"Eavesdrop TDMA MAC Slots",
	"Eavesdrop V2X",
	"Cell Tower Localisation",
	"ISMI Catchers",
	"Eavesdrop Bluetooth",
	"Eavesdrop WiFI",
	"Driving Style and Behaviour",
	"Database Leak",
], start=1))

# Check threats and techniques have been specified correctly
for (name, threat) in threats.items():
	possible_techniques = threat_technique_mappings[threat]

	if techniques[name] not in possible_techniques:
		raise RuntimeError(f"Bad Technique Specification for {name} ({techniques[name]} not in {possible_techniques})")

def conv(x):
	return {
		Technique.No: "|[fill=nothing]|",
		Technique.JamSignal: "|[fill=jam]|",
		Technique.PerturbIdentity: "|[fill=identity]|",
		Technique.PerturbContents: "|[fill=body]|",
		Technique.ChangeCommunicationPatterns: "|[fill=comms]|",
		Technique.ChangeBehaviouralPatterns: "|[fill=patterns]|",
		Technique.PerturbIdentity|Technique.ChangeCommunicationPatterns: "|[fill=identityandcomms]|",
		Technique.PerturbIdentity|Technique.ChangeBehaviouralPatterns: "|[fill=identityandpatterns]|",
		Technique.PerturbContents|Technique.ChangeCommunicationPatterns: "|[fill=bodyandcomms]|",
		Technique.PerturbContents|Technique.ChangeBehaviouralPatterns: "|[fill=bodyandpatterns]|",
		Technique.PerturbContents|Technique.PerturbIdentity: "|[fill=bodyandidentity]|",
		Technique.PerturbContents|Technique.ChangeBehaviouralPatterns|Technique.PerturbIdentity: "|[fill=bodyandpatternsandidentity]|",
		Technique.PerturbContents|Technique.ChangeCommunicationPatterns|Technique.PerturbIdentity: "|[fill=bodyandcommsandidentity]|",
	}[x]

def combine(technique_left, technique_top, left, top):
	if technique_left == technique_top:
		return "|[fill=same]|", technique_left

	if left == Technique.No or top == Technique.No:
		return conv(Technique.No), Technique.No

	# What techniques are used by both
	comb = left & top

	left_poss = threat_technique_mappings[threats[technique_left]]
	top_poss = threat_technique_mappings[threats[technique_top]]

	# Are any techniques in top applicable to left?
	comb |= top & left_poss

	# Can't consider techniques that are not possible on the left
	comb &= left_poss

	if comb:
		return conv(comb), comb

	return "", comb

def combine_threat(left, top):
	if left == top:
		return "|[fill=same]|"

	left_poss = threat_technique_mappings[left]
	top_poss = threat_technique_mappings[top]

	comb = left_poss & top_poss

	if comb:
		return conv(comb)

	return ""

def combine_triangles(i, j, ct):
	colors = []

	tcs = {
		Technique.PerturbIdentity: "identity",
		Technique.PerturbContents: "body",
		Technique.ChangeCommunicationPatterns: "comms",
		Technique.ChangeBehaviouralPatterns: "patterns",
	}

	for (t, c) in tcs.items():
		if t & ct:
			colors.append(c)

	s2 = f"\\draw[fill={{}}] (mat11-{i}-{j}.north west) -- (mat11-{i}-{j}.south west) -- (mat11-{i}-{j}.south east) -- cycle;\n\\draw[fill={{}}] (mat11-{i}-{j}.north west) -- (mat11-{i}-{j}.north east) -- (mat11-{i}-{j}.south east) -- cycle;"

	assert len(colors) == 2

	return s2.format(colors[0], colors[1])

def print_main_matrix(f):
	print(r"\matrix[table] (mat11)", file=f)
	print(r"{", file=f)

	triangles = []
	for (i, technique_left) in output_order:
		left = techniques.get(technique_left)

		cs = []

		for (j, technique_top) in output_order:
			top = techniques.get(technique_top)
			c, ct = combine(technique_left, technique_top, left, top)

			cs.append(c)

			if "and" in c:
				triangles.append(combine_triangles(i, j, ct))
		
		print(" & ".join(cs) + "\\\\", file=f)

	print(r"};", file=f)
	print("\n".join(triangles), file=f)
	print(r"", file=f)

	for (i, name) in output_order:
		print(f"\\SlText{{11-1-{i}}} {{{name}}} \\CellText{{11-{i}-1}} {{{name}}}", file=f)

def print_legend_matrix(f):
	print(r"\matrix[table,right=of mat11] (mat12)", file=f)
	print(r"{", file=f)
	print(r"|[fill=jam]| \\", file=f)
	print(r"|[fill=identity]| \\", file=f)
	print(r"|[fill=body]| \\", file=f)
	print(r"|[fill=comms]| \\", file=f)
	print(r"|[fill=patterns]| \\[1mm]", file=f)
	print(r"|[fill=same]| \\", file=f)
	print(r"|[fill=nothing]| \\", file=f)
	print(r"};", file=f)
	print(r"", file=f)
	print(r"\RowTitle{12}{Legend: How may aspects of existing solution for threat on left need to be adjusted to consider threat on top};", file=f)
	print(r"\CellTextRight{12-1-1}{Jam Signals};", file=f)
	print(r"\CellTextRight{12-2-1}{Perturb Identity};", file=f)
	print(r"\CellTextRight{12-3-1}{Perturb Contents};", file=f)
	print(r"\CellTextRight{12-4-1}{Change Communications};", file=f)
	print(r"\CellTextRight{12-5-1}{Change Behaviour};", file=f)
	print(r"\CellTextRight{12-6-1}{Same Technique};", file=f)
	print(r"\CellTextRight{12-7-1}{No Solution / Interaction};", file=f)


def main_threat_matrix(f):
	print(r"\documentclass[border=10pt]{standalone}", file=f)
	print(r"\usepackage[dvipsnames,cmyk]{xcolor}", file=f)
	print(r"\usepackage[normalem]{ulem}", file=f)
	print(r"\usepackage{tikz}", file=f)
	print(r"\usetikzlibrary{positioning,chains,fit,shapes,calc,matrix}", file=f)
	print(r"", file=f)
	print(r"\definecolor{same}{cmyk}{0,0,0,0.2}", file=f)
	print(r"\definecolor{jam}{cmyk}{0,0,0,0.5}", file=f)
	print(r"\definecolor{identity}{cmyk}{1,0,0,0}", file=f)
	print(r"\definecolor{body}{cmyk}{0,1,0,0}", file=f)
	print(r"\definecolor{comms}{cmyk}{0,0,1,0}", file=f)
	print(r"\definecolor{patterns}{cmyk}{0,0,0,0.8}", file=f)
	print(r"\colorlet{nothing}{white}", file=f)
	print(r"\colorlet{identityandcomms}{white}", file=f)
	print(r"\colorlet{identityandpatterns}{white}", file=f)
	print(r"\colorlet{bodyandcomms}{white}", file=f)
	print(r"\colorlet{bodyandpatterns}{white}", file=f)
	print(r"\colorlet{bodyandidentity}{white}", file=f)
	print(r"", file=f)
	print(r"\tikzset{", file=f)
	print(r"table/.style={", file=f)
	print(r"  matrix of nodes,", file=f)
	print(r"  row sep=-\pgflinewidth,", file=f)
	print(r"  column sep=-\pgflinewidth,", file=f)
	print(r"  nodes={rectangle,draw=black,text width=1.25ex,align=center},", file=f)
	print(r"  text depth=0.25ex,", file=f)
	print(r"  text height=1ex,", file=f)
	print(r"  nodes in empty cells", file=f)
	print(r"  },", file=f)
	print(r"texto/.style={font=\footnotesize\sffamily},", file=f)
	print(r"title/.style={font=\small\sffamily}", file=f)
	print(r"}", file=f)
	print(r"\newcommand\CellText[2]{%", file=f)
	print(r"  \node[texto,left=of mat#1,anchor=east]", file=f)
	print(r"  at (mat#1.west)", file=f)
	print(r"  {#2};", file=f)
	print(r"}", file=f)
	print(r"", file=f)
	print(r"\newcommand\SlText[2]{%", file=f)
	print(r"  \node[texto,left=of mat#1,anchor=west,rotate=75]", file=f)
	print(r"  at ([xshift=3ex]mat#1.north)", file=f)
	print(r"  {#2};", file=f)
	print(r"}", file=f)
	print(r"", file=f)
	print(r"\newcommand\CellTextRight[2]{%", file=f)
	print(r"  \node[texto,left=of mat#1,anchor=west,align=left]", file=f)
	print(r"  at ([xshift=7ex]mat#1.west)", file=f)
	print(r"  {#2};", file=f)
	print(r"}", file=f)
	print(r"", file=f)
	print(r"\newcommand\RowTitle[2]{%", file=f)
	print(r"\node[title,above=of mat#1,anchor=north,text width=4cm]", file=f)
	print(r"  at ([yshift=11ex,xshift=12ex]mat#1.north)", file=f)
	print(r"  {#2};", file=f)
	print(r"}", file=f)
	print(r"", file=f)
	print(r"\begin{document}", file=f)
	print(r"", file=f)
	print(r"\begin{tikzpicture}[node distance =0pt and 0.5cm]", file=f)
	print(r"", file=f)
	print_main_matrix(f)
	print(r"", file=f)
	print_legend_matrix(f)
	print(r"", file=f)
	print(r"\node[texto,left=of mat11,anchor=west,rotate=90]", file=f)
	print(r"  at ([xshift=-26ex]mat11.west)", file=f)
	print(r"  {Existing Privacy Solution For:};", file=f)
	print(r"  ", file=f)
	print(r"\node[texto,above=of mat11,anchor=north]", file=f)
	print(r"  at ([yshift=28ex]mat11.north)", file=f)
	print(r"  {Want to Extend to Consider Privacy For:};", file=f)
	print(r"\end{tikzpicture}", file=f)
	print(r"\end{document}", file=f)

def main_threat_technique_mapping(f):
	# From: https://tex.stackexchange.com/questions/15088/bipartite-graphs
	print(r"\documentclass[border=0pt]{standalone}", file=f)
	print(r"\usepackage{tikz}", file=f)
	print(r"\usetikzlibrary{positioning,chains,fit,shapes,calc}", file=f)
	print(r"\begin{document}", file=f)
	print(r"\large", file=f)
	print(r"", file=f)
	print(r"\definecolor{myblue}{RGB}{80,80,160}", file=f)
	print(r"\definecolor{mygreen}{RGB}{80,160,80}", file=f)
	print(r"", file=f)
	print(r"\begin{tikzpicture}[thick,", file=f)
	print(r"  fsnode/.style={draw,circle,fill=myblue,text=white},", file=f)
	print(r"  ssnode/.style={draw,circle,fill=mygreen},", file=f)
	print(r"  ->,shorten >= 3pt,shorten <= 3pt", file=f)
	print(r"]", file=f)
	print(r"", file=f)
	print(r"% the vertices of Threats", file=f)
	print(r"\begin{scope}[local bounding box=scope1,start chain=going below,node distance=5mm]", file=f)
	for threat in Threat:
		print(f"\\node[fsnode,on chain] (T{threat.value}) [label=left: {threat.label}] {{$\\mathbf{{T_{threat.letter}}}$}};", file=f)
	#print(r"\node[fsnode,on chain] (T0) [label=left: Direct Access] {$\mathbf{T_A}$};")
	#print(r"\node[fsnode,on chain] (T1) [label=left: Visual Identification] {$\mathbf{T_B}$};")
	#print(r"\node[fsnode,on chain] (T2a) [label=left: Internal Vehicle Communication] {$\mathbf{T_D}$};")
	#print(r"\node[fsnode,on chain] (T2b) [label=left: External Vehicle Communication] {$\mathbf{T_E}$};")
	#print(r"\node[fsnode,on chain] (T3) [label=left: Non-vehicle Communication] {$\mathbf{T_F}$};")
	#print(r"\node[fsnode,on chain] (T4) [label=left: Behavioural] {$\mathbf{T_G}$};")
	#print(r"\node[fsnode,on chain] (T8) [label=left: Services] {$\mathbf{T_C}$};")
	#print(r"\node[fsnode,on chain] (T9) [label=left: Historical] {$\mathbf{T_H}$};")
	print(r"\end{scope}", file=f)
	print(r"", file=f)
	print(r"% the vertices of Solutions", file=f)
	print(r"\begin{scope}[local bounding box=scope2,start chain=going below,node distance=5mm,xshift=3.4cm]", file=f)
	for technique in Technique:
		if technique:
			print(f"\\node[ssnode,on chain] (S{technique.value}) [label=right: {technique.label}] {{$\\mathbf{{P_{technique.letter}}}$}};", file=f)
	print(r"\end{scope}", file=f)
	print(r"", file=f)
	for (threat, mapped_techniques) in threat_technique_mappings.items():
		for technique in Technique:
			if technique and technique in mapped_techniques:
				print(f"\\draw (T{threat.value}) -- (S{technique.value});", file=f)
	print(r"", file=f)
	print(r"\end{tikzpicture}", file=f)
	print(r"", file=f)
	print(r"\end{document}", file=f)

if __name__ == "__main__":
	with open("threat-overlap-matrix.tex", "w") as tm:
		main_threat_matrix(tm)

	with open("bipartite-graph.tex", "w") as ttm:
		main_threat_technique_mapping(ttm)
