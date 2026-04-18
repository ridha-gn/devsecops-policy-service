from typing import Dict, Any, List
from models.code_structure import NormalizedCode, Resource


class Normalizer:
    
    def normalize_terraform(self, parsed_data: Dict, resources: List[Dict]) -> NormalizedCode:
        normalized_resources = []
        
        for resource in resources:
            normalized_resources.append(
                Resource(
                    resource_type=resource["type"],
                    resource_name=resource["name"],
                    attributes=resource["attributes"],
                    line_number=resource.get("line")
                )
            )
        
        variables = {}
        for var_block in parsed_data.get("variable", []):
            for var_name, var_config in var_block.items():
                variables[var_name] = var_config
        
        return NormalizedCode(
            code_type="terraform",
            resources=normalized_resources,
            variables=variables,
            metadata={"provider": parsed_data.get("provider", [])}
        )
    
    def normalize_dockerfile(self, parsed_data: Dict) -> NormalizedCode:
        resources = []
        
        for instruction in parsed_data.get("instructions", []):
            resources.append(
                Resource(
                    resource_type=f"docker_{instruction['instruction'].lower()}",
                    resource_name=instruction['instruction'],
                    attributes={"args": instruction["args"]},
                    line_number=instruction.get("line")
                )
            )
        
        return NormalizedCode(
            code_type="dockerfile",
            resources=resources,
            variables={},
            metadata={}
        )
    
    def normalize_kubernetes(self, parsed_data: Dict, parser) -> NormalizedCode:
        resources = []
        
        kind = parsed_data.get("kind", "Unknown")
        metadata = parsed_data.get("metadata", {})
        name = metadata.get("name", "unnamed")
        
        containers = parser.extract_containers(parsed_data)
        
        for idx, container in enumerate(containers):
            container_name = container.get("name", f"container-{idx}")
            
            security_context = container.get("securityContext", {})
            
            resources.append(
                Resource(
                    resource_type=f"k8s_{kind.lower()}_container",
                    resource_name=container_name,
                    attributes={
                        "image": container.get("image", ""),
                        "securityContext": security_context,
                        "privileged": security_context.get("privileged", False),
                        "runAsUser": security_context.get("runAsUser"),
                        "resources": container.get("resources", {}),
                        "parent_name": name
                    },
                    line_number=1
                )
            )
        
        if kind in ["Pod", "Deployment"]:
            spec = parsed_data.get("spec", {})
            if kind == "Deployment":
                spec = spec.get("template", {}).get("spec", {})
            
            host_network = spec.get("hostNetwork", False)
            if host_network:
                resources.append(
                    Resource(
                        resource_type="k8s_host_network",
                        resource_name=name,
                        attributes={"hostNetwork": True},
                        line_number=1
                    )
                )
        
        return NormalizedCode(
            code_type="kubernetes",
            resources=resources,
            variables={},
            metadata={"kind": kind, "name": name}
        )
    
    def normalize(self, code_type: str, parsed_data: Dict, extracted_resources: List = None, parser=None) -> NormalizedCode:
        if code_type == "terraform":
            return self.normalize_terraform(parsed_data, extracted_resources or [])
        elif code_type == "dockerfile":
            return self.normalize_dockerfile(parsed_data)
        elif code_type == "yaml":
            return self.normalize_kubernetes(parsed_data, parser)
        else:
            raise ValueError(f"Unsupported code type: {code_type}")