#!/usr/bin/env python3

import argparse
import sys
from ldap3 import Server, Connection, ALL, NTLM

class ADQuerier:
    def __init__(self, dc_ip, username, password, domain=None):
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.connection = None
        self.domain_name = None
        
    def connect(self):
        """Establish connection to domain controller"""
        server = Server(self.dc_ip, get_info=ALL)
        
        # Try different auth types
        try:
            # domain\username 
            if self.domain:
                user_dn = f"{self.domain}\\{self.username}"
            elif '\\' in self.username:
                # Username already contains domain
                user_dn = self.username
            elif '@' in self.username:
                # UPN format - try to extract domain
                user_dn = self.username
                if not self.domain:
                    self.domain = self.username.split('@')[1]
            else:
                # No domain provided try resolving it
                print("Warning: No domain specified. Attempting anonymous connection first to discover domain...")
                try:
                    temp_conn = Connection(server, auto_bind=True)
                    if server.info and server.info.naming_contexts:
                        domain_dn = server.info.naming_contexts[0]
                        # Extract domain from DN (e.g., DC=example,DC=com -> example.com)
                        domain_parts = [part.split('=')[1] for part in domain_dn.split(',') if part.startswith('DC=')]
                        self.domain = '.'.join(domain_parts)
                        user_dn = f"{self.domain}\\{self.username}"
                        temp_conn.unbind()
                    else:
                        user_dn = self.username
                except:
                    user_dn = self.username
            
            self.connection = Connection(
                server, 
                user=user_dn, 
                password=self.password, 
                authentication=NTLM,
                auto_bind=True
            )
            
        except Exception as e:
            print(f"NTLM authentication failed: {e}")
            print("Trying simple authentication...")
            try:
                # simple auth
                self.connection = Connection(
                    server,
                    user=self.username,
                    password=self.password,
                    auto_bind=True
                )
            except Exception as e2:
                print(f"Simple authentication also failed: {e2}")
                return False
        
        # Get base DN from server info
        if server.info and server.info.naming_contexts:
            self.domain_name = server.info.naming_contexts[0]
        else:
            if self.domain:
                domain_parts = self.domain.split('.')
                self.domain_name = ','.join([f'DC={part}' for part in domain_parts])
            else:
                print("Could not determine base DN")
                return False
        
        print(f"Connected to domain controller: {self.dc_ip}")
        print(f"Base DN: {self.domain_name}")
        return True
    
    def query_users(self):
        """Query all domain users"""
        if not self.connection:
            return []
        
        search_filter = '(&(objectClass=user)(objectCategory=person))'
        attributes = [
            'sAMAccountName', 'displayName', 'mail', 'userPrincipalName',
            'whenCreated', 'whenChanged', 'lastLogon', 'userAccountControl',
            'memberOf', 'description'
        ]
        
        self.connection.search(
            search_base=self.domain_name,
            search_filter=search_filter,
            attributes=attributes
        )
        
        users = []
        for entry in self.connection.entries:
            user_info = {
                'Username': str(entry.sAMAccountName),
                'Display Name': str(entry.displayName),
                'Email': str(entry.mail),
                'UPN': str(entry.userPrincipalName),
                'Created': str(entry.whenCreated),
                'Modified': str(entry.whenChanged),
                'Description': str(entry.description),
                'Account Control': str(entry.userAccountControl),
                'Groups': [str(group) for group in entry.memberOf] if entry.memberOf else []
            }
            users.append(user_info)
        
        return users
    
    def query_groups(self):
        """Query all domain groups"""
        if not self.connection:
            return []
        
        search_filter = '(objectClass=group)'
        attributes = [
            'sAMAccountName', 'displayName', 'description', 'whenCreated',
            'whenChanged', 'member', 'groupType'
        ]
        
        self.connection.search(
            search_base=self.domain_name,
            search_filter=search_filter,
            attributes=attributes
        )
        
        groups = []
        for entry in self.connection.entries:
            group_info = {
                'Group Name': str(entry.sAMAccountName),
                'Display Name': str(entry.displayName),
                'Description': str(entry.description),
                'Created': str(entry.whenCreated),
                'Modified': str(entry.whenChanged),
                'Group Type': str(entry.groupType),
                'Members': [str(member) for member in entry.member] if entry.member else []
            }
            groups.append(group_info)
        
        return groups
    
    def query_computers(self):
        """Query all domain computers"""
        if not self.connection:
            return []
        
        search_filter = '(objectClass=computer)'
        attributes = [
            'sAMAccountName', 'dNSHostName', 'operatingSystem',
            'operatingSystemVersion', 'whenCreated', 'whenChanged',
            'lastLogon', 'description'
        ]
        
        self.connection.search(
            search_base=self.domain_name,
            search_filter=search_filter,
            attributes=attributes
        )
        
        computers = []
        for entry in self.connection.entries:
            computer_info = {
                'Computer Name': str(entry.sAMAccountName),
                'DNS Name': str(entry.dNSHostName),
                'Operating System': str(entry.operatingSystem),
                'OS Version': str(entry.operatingSystemVersion),
                'Created': str(entry.whenCreated),
                'Modified': str(entry.whenChanged),
                'Description': str(entry.description)
            }
            computers.append(computer_info)
        
        return computers
    
    def query_organizational_units(self):
        """Query organizational units"""
        if not self.connection:
            return []
        
        search_filter = '(objectClass=organizationalUnit)'
        attributes = ['ou', 'description', 'whenCreated', 'whenChanged']
        
        self.connection.search(
            search_base=self.domain_name,
            search_filter=search_filter,
            attributes=attributes
        )
        
        ous = []
        for entry in self.connection.entries:
            ou_info = {
                'OU Name': str(entry.ou),
                'Description': str(entry.description),
                'Created': str(entry.whenCreated),
                'Modified': str(entry.whenChanged),
                'Distinguished Name': str(entry.entry_dn)
            }
            ous.append(ou_info)
        
        return ous
    
    def disconnect(self):
        """Close connection"""
        if self.connection:
            self.connection.unbind()

def format_output(data, title):
    """Format data for display"""
    output = []
    output.append(f"\n{'='*60}")
    output.append(f"{title.upper()}")
    output.append(f"{'='*60}")
    output.append(f"Total count: {len(data)}\n")
    
    for i, item in enumerate(data, 1):
        output.append(f"{i}. ")
        for key, value in item.items():
            if isinstance(value, list) and value:
                output.append(f"   {key}: {', '.join(value[:3])}")
                if len(value) > 3:
                    output.append(f" ... (+{len(value)-3} more)")
            else:
                output.append(f"   {key}: {value}")
        output.append("")
    
    return '\n'.join(output)

def save_to_file(content, filename):
    """Save output to file"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Results saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="Query Active Directory Domain Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ad_query.py -s 192.168.1.10 -u administrator -p password123 -d DOMAIN
  python ad_query.py -s dc.company.local -u admin@company.local -p pass
  python ad_query.py -s 10.0.0.1 -u "DOMAIN\\admin" -p password --users-only
  
Authentication formats:
  - Domain\\Username (requires -d domain or username with domain)
  - user@domain.com (UPN)
  - administrator (local admin, may work without domain)
        """
    )
    
    parser.add_argument('-s', '--server', required=True,
                       help='Domain controller IP address or hostname')
    parser.add_argument('-u', '--username', required=True,
                       help='Username for authentication')
    parser.add_argument('-p', '--password', required=True,
                       help='Password for authentication')
    parser.add_argument('-d', '--domain',
                       help='Domain name (optional)')
    parser.add_argument('-o', '--output',
                       help='Output file to save results')
    
    # Query parameters
    parser.add_argument('--users-only', action='store_true',
                       help='Query only users')
    parser.add_argument('--groups-only', action='store_true',
                       help='Query only groups')
    parser.add_argument('--computers-only', action='store_true',
                       help='Query only computers')
    parser.add_argument('--ous-only', action='store_true',
                       help='Query only organizational units')
    
    args = parser.parse_args()
    
    print("""
██████  ██  ██████  ██████  
██   ██ ██ ██    ██ ██   ██ 
██   ██ ██ ██    ██ ██████  
██   ██ ██ ██    ██ ██   ██ 
██████  ██  ██████  ██   ██ 
                            
Domain Info Over RPC
""")
    print("=" * 40)
    
    # Initialize the query
    con_attempt = ADQuerier(args.server, args.username, args.password, args.domain)
    
    # Connect to DC
    if not con_attempt.connect():
        print("\nConnection failed. Please check:")
        print("1. Server IP/hostname is correct and reachable")
        print("2. Username and password are correct")
        print("3. Domain name is specified (use -d option)")
        print("4. Try using domain\\username format or user@domain.com")
        print("\nExamples:")
        print("  python script.py -s 192.168.1.10 -u 'DOMAIN\\admin' -p password")
        print("  python script.py -s dc.local -u admin@domain.com -p password")
        sys.exit(1)
    
    all_output = ""
    
    try:
        # query calls
        query_all = not any([args.users_only, args.groups_only, 
                           args.computers_only, args.ous_only])
        
        if args.users_only or query_all:
            print("\nQuerying domain users...")
            users = con_attempt.query_users()
            output = format_output(users, "Domain Users")
            print(output)
            all_output += output
        
        if args.groups_only or query_all:
            print("\nQuerying domain groups...")
            groups = con_attempt.query_groups()
            output = format_output(groups, "Domain Groups")
            print(output)
            all_output += output
        
        if args.computers_only or query_all:
            print("\nQuerying domain computers...")
            computers = con_attempt.query_computers()
            output = format_output(computers, "Domain Computers")
            print(output)
            all_output += output
        
        if args.ous_only or query_all:
            print("\nQuerying organizational units...")
            ous = con_attempt.query_organizational_units()
            output = format_output(ous, "Organizational Units")
            print(output)
            all_output += output
        
        # outfile
        if args.output:
            save_to_file(all_output, args.output)
    
    except Exception as e:
        print(f"\nError during query execution: {e}")
        sys.exit(1)
    
    finally:
        con_attempt.disconnect()
        print("\nQuery completed")

if __name__ == "__main__":
    main()
