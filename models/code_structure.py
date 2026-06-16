from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class Resource:
    resource_type: str
    resource_name: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    line_number: Optional[int] = None

    def get_attribute(self, key: str, default: Any = None) -> Any:
        return self.attributes.get(key, default)

    def has_attribute(self, key: str) -> bool:
        return key in self.attributes


@dataclass
class NormalizedCode:
    code_type: str
    resources: List[Resource] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def find_resources_by_type(self, resource_type: str) -> List[Resource]:
        return [r for r in self.resources if r.resource_type == resource_type]

    def find_resource_by_name(self, name: str) -> Optional[Resource]:
        for resource in self.resources:
            if resource.resource_name == name:
                return resource
        return None

    def has_resource_type(self, resource_type: str) -> bool:
        return any(r.resource_type == resource_type for r in self.resources)
