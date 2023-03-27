from dataclasses import dataclass
from typing import Optional, TypedDict


class Block(TypedDict):
	changeType: int
	"""
	The type of change.
	0 means no change, 1 means added, 2 means removed.
	3 can happen, it's unclear what is means.
	Maybe it's a conflict?
	Maybe it's something that is in the target branch (e.g., main), but not pulled in the PR branch yet?
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
	change_type: str
	path: str
	original_path: Optional[str] = None
	diff: Optional[Diff] = None
	contents: Optional[str] = None
	"""
	The contents when the change type is 'add'.
	"""
