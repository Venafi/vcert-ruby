# VCert Ruby

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>  
 
VCert Ruby is a Ruby library and SDK  designed to simplify key generation and enrollment of machine identities
(also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://pki.venafi.com/venafi-cloud/).

This implementation is based on the original Go library, https://github.com/Venafi/vcert.

#### Compatibility
VCert supports Ruby 2.3+.  VCert releases are tested using the latest version of Trust Protection Platform.  The [latest VCert release](../../releases/latest) should be compatible with Trust Protection Platform 17.3 or higher based on the subset of API methods it consumes.

## Installation
Get the library using gem:  
`gem install vcert`  

You also can install latest version from github:  
`gem specific_install https://github.com/Venafi/vcert-ruby.git`

## Usage example

For code samples of programmatic use, please review the files in [/examples](/examples).

## Prerequisites for using with Trust Protection Platform

1. A user account that has been granted WebSDK Access
2. A folder (zone) where the user has been granted the following permissions: View, Read, Write, Create, Revoke (for the revoke action), and Private Key Read (for the pickup action when CSR is service generated)
3. Policy applied to the folder which specifies:
    1. CA Template that Trust Protection Platform will use to enroll certificate requests submitted by VCert
    2. Subject DN values for Organizational Unit (OU), Organization (O), City (L), State (ST) and Country (C)
    3. Management Type not locked or locked to 'Enrollment'
    4. Certificate Signing Request (CSR) Generation not locked or locked to 'Service Generated CSR'
    5. Generate Key/CSR on Application not locked or locked to 'No'
    6. (Recommended) Disable Automatic Renewal set to 'Yes'
    7. (Recommended) Key Bit Strength set to 2048 or higher
    8. (Recommended) Domain Whitelisting policy appropriately assigned

## Contributing to VCert

Venafi welcomes contributions from the developer community.

1. Fork it to your account (https://github.com/Venafi/vcert-ruby/fork)
2. Clone your fork (`git clone git@github.com:youracct/vcert-ruby.git`)
3. Create a feature branch (`git checkout -b your-branch-name`)
4. Implement and test your changes
5. Commit your changes (`git commit -am 'Added some cool functionality'`)
6. Push to the branch (`git push origin your-branch-name`)
7. Create a new Pull Request (https://github.com/youracct/vcert-ruby/pull/new/your-branch-name)

## License

Copyright &copy; Venafi, Inc. All rights reserved.

VCert is licensed under the Apache License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.
