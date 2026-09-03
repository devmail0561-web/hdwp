# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from pydantic import BaseModel


class ScanStatusResponse(BaseModel):
    status: str
    session_id: str
