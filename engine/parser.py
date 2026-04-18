import hcl2
import json
import yaml
from typing import Dict, Any, Optional


class TerraformParser:
    
    @staticmethod
    def _strip_quotes(value):
        """Strip extra quotes added by python-hcl2 v8.x.
        
        The newer version wraps keys and string values in escaped quotes:
        e.g. '"aws_s3_bucket"' instead of 'aws_s3_bucket'
             '"public-read"' instead of 'public-read'
        This method recursively strips those extra quotes.
        """
        if isinstance(value, str):
            # Strip surrounding quotes: '"public-read"' -> 'public-read'
            if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
                return value[1:-1]
            return value
        elif isinstance(value, dict):
            return {
                TerraformParser._strip_quotes(k): TerraformParser._strip_quotes(v)
                for k, v in value.items()
                if k != '__is_block__'  # Remove internal marker
            }
        elif isinstance(value, list):
            return [TerraformParser._strip_quotes(item) for item in value]
        else:
            return value
    
    def parse(self, content: str) -> Dict[str, Any]:
        try:
            parsed = hcl2.loads(content)
            # Clean up extra quotes from python-hcl2 v8.x
            parsed = self._strip_quotes(parsed)
            return parsed
        except Exception as e:
            raise ValueError(f"Failed to parse Terraform: {str(e)}")
    
    def extract_resources(self, parsed_data: Dict) -> list:
        resources = []
        line_number = 1
        
        for resource_block in parsed_data.get("resource", []):
            for resource_type, instances in resource_block.items():
                if isinstance(instances, dict):
                    for resource_name, attributes in instances.items():
                        if isinstance(attributes, dict):
                            resources.append({
                                "type": resource_type,
                                "name": resource_name,
                                "attributes": attributes,
                                "line": line_number
                            })
                            line_number += 10
        
        return resources
    
    def extract_providers(self, parsed_data: Dict) -> list:
        providers = []
        
        for provider_block in parsed_data.get("provider", []):
            for provider_name, config in provider_block.items():
                if isinstance(config, dict):
                    providers.append({
                        "name": provider_name,
                        "config": config
                    })
        
        return providers


class DockerfileParser:
    
    def parse(self, content: str) -> Dict[str, Any]:
        instructions = []
        line_number = 0
        
        for line in content.split('\n'):
            line_number += 1
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            parts = line.split(maxsplit=1)
            if len(parts) >= 1:
                instruction = parts[0].upper()
                args = parts[1] if len(parts) > 1 else ""
                
                instructions.append({
                    "instruction": instruction,
                    "args": args,
                    "line": line_number
                })
        
        return {"instructions": instructions}
    
    def extract_base_image(self, parsed_data: Dict) -> Optional[str]:
        for instruction in parsed_data.get("instructions", []):
            if instruction["instruction"] == "FROM":
                return instruction["args"]
        return None
    
    def extract_user(self, parsed_data: Dict) -> Optional[str]:
        for instruction in parsed_data.get("instructions", []):
            if instruction["instruction"] == "USER":
                return instruction["args"]
        return None


class KubernetesParser:
    
    def parse(self, content: str) -> Dict[str, Any]:
        try:
            parsed = yaml.safe_load(content)
            if parsed is None:
                raise ValueError("Empty YAML content")
            return parsed
        except Exception as e:
            raise ValueError(f"Failed to parse Kubernetes YAML: {str(e)}")
    
    def extract_pods(self, parsed_data: Dict) -> list:
        pods = []
        
        kind = parsed_data.get("kind", "")
        
        if kind == "Pod":
            pods.append(parsed_data)
        elif kind == "Deployment":
            pod_template = parsed_data.get("spec", {}).get("template", {})
            if pod_template:
                pods.append(pod_template)
        
        return pods
    
    def extract_containers(self, parsed_data: Dict) -> list:
        containers = []
        
        pods = self.extract_pods(parsed_data)
        
        for pod in pods:
            pod_spec = pod.get("spec", {})
            containers.extend(pod_spec.get("containers", []))
        
        return containers


def get_parser(code_type: str):
    if code_type == "terraform":
        return TerraformParser()
    elif code_type == "dockerfile":
        return DockerfileParser()
    elif code_type == "yaml":
        return KubernetesParser()
    else:
        raise ValueError(f"Unsupported code type: {code_type}")