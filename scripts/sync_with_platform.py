import argparse
import json
import sys
import requests
from typing import Dict, Any
from urllib.parse import urljoin


class AutoThreatSync:
    """Handles synchronization of SBOM data with AutoThreat platform."""

    def __init__(self, api_key: str, base_url: str):
        """
        Initialize the AutoThreat sync client.

        Args:
            api_key: API key for authentication
            base_url: Base URL for the AutoThreat API
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'AutoThreat-Action/1.0'
        })

    def read_sbom_file(self, sbom_path: str) -> Dict[str, Any]:
        """
        Read and parse the SBOM JSON file.

        Args:
            sbom_path: Path to the SBOM JSON file

        Returns:
            Parsed SBOM data as dictionary

        Raises:
            FileNotFoundError: If the SBOM file doesn't exist
            json.JSONDecodeError: If the file contains invalid JSON
        """
        try:
            with open(sbom_path, 'r', encoding='utf-8') as f:
                sbom_data = json.load(f)
            return sbom_data
        except FileNotFoundError:
            raise FileNotFoundError(f"SBOM file not found: {sbom_path}")
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"Invalid JSON in SBOM file: {e}", e.doc, e.pos)

    def validate_sbom_data(self, sbom_data: Dict[str, Any]) -> bool:
        """
        Validate the SBOM data structure.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            True if valid, False otherwise
        """
        # Basic validation - check for required fields
        required_fields = ['spdxVersion', 'dataLicense', 'SPDXID', 'name']
        if not all(field in sbom_data for field in required_fields):
            print("Warning: SBOM data may not be in SPDX format")
            return False
        return True

    def sync_sbom(self, sbom_data: Dict[str, Any], project_name: str) -> Dict[str, Any]:
        """
        Sync SBOM data with the AutoThreat platform.

        Args:
            sbom_data: Parsed SBOM data
            project_name: Name of the project/repository

        Returns:
            Response from the API

        Raises:
            requests.RequestException: If the API request fails
        """
        endpoint = "/sbom/sync"
        url = urljoin(self.base_url + '/', endpoint.lstrip('/'))

        payload = {
            'project': project_name,
            'sbom': sbom_data,
            'metadata': {
                'source': 'github-action',
                'timestamp': self._get_current_timestamp()
            }
        }

        try:
            print(f"Syncing SBOM data for project: {project_name}")
            print(f"API Endpoint: {url}")

            response = self.session.post(url, json=payload, timeout=30)

            # Raise an exception for bad status codes
            response.raise_for_status()

            result = response.json()
            print(f"Successfully synced SBOM data. Response: {result}")
            return result

        except requests.exceptions.Timeout:
            raise requests.RequestException("Request timed out")
        except requests.exceptions.ConnectionError:
            raise requests.RequestException("Connection error")
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP error {e.response.status_code}"
            if e.response.text:
                try:
                    error_data = e.response.json()
                    error_msg += f": {error_data.get('message', e.response.text)}"
                except json.JSONDecodeError:
                    error_msg += f": {e.response.text}"
            raise requests.RequestException(error_msg)
        except requests.exceptions.RequestException as e:
            raise requests.RequestException(f"Request failed: {str(e)}")

    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, UTC
        return datetime.now(UTC).isoformat()


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Sync SBOM data with AutoThreat platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 sync_with_platform.py --sbom sbom.json --api-key your-api-key --project owner/repo
  python3 sync_with_platform.py --sbom ./build/sbom.json --api-key $AUTO_THREAT_API_KEY --project ${{ github.repository }}
        """
    )

    parser.add_argument(
        '--sbom',
        required=True,
        help='Path to the SBOM JSON file'
    )

    parser.add_argument(
        '--api-key',
        required=True,
        help='AutoThreat API key for authentication'
    )

    parser.add_argument(
        '--project',
        required=True,
        help='Project name in format owner/repo (e.g., octocat/hello-world)'
    )

    parser.add_argument(
        '--api-url',
        default='http://autothreat.vercel.app/api',
        help='AutoThreat API base URL (default: https://autothreat.vercel.app/api)',
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Enable verbose logging if requested
    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    try:
        # Initialize the sync client
        print("Initializing AutoThreat sync client...")
        sync_client = AutoThreatSync(args.api_key, args.api_url)

        # Read and validate SBOM file
        print(f"Reading SBOM file: {args.sbom}")
        sbom_data = sync_client.read_sbom_file(args.sbom)

        # Validate SBOM data (optional but recommended)
        if sync_client.validate_sbom_data(sbom_data):
            print("SBOM data validation passed")
        else:
            print("Warning: SBOM data validation failed, proceeding anyway...")

        # Sync with platform
        result = sync_client.sync_sbom(sbom_data, args.project)

        # Success
        print("✅ SBOM sync completed successfully!")
        if 'id' in result:
            print(f"Sync ID: {result['id']}")
        if 'status' in result:
            print(f"Status: {result['status']}")

        # Exit with success
        sys.exit(0)

    except FileNotFoundError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"❌ API Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()