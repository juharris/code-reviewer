from dataclasses import dataclass
from typing import TypedDict


class Block(TypedDict):
	changeType: int
	"""
	The type of change.
	0 means no change, 1 means added, 2 means removed.
	3 can happen, it's unclear what is means. Maybe it's a conflict?
	"""

	mLines: list[str]
	mLine: int
	mLinesCount: int
	
	oLine: int
	oLines: list[str]
	oLinesCount: int

	truncatedBefore: bool

class Diff(TypedDict):
	blocks: list[Block]

@dataclass
class FileDiff:
	original_path: str
	modified_path: str
	diff: Diff
