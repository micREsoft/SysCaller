from PyQt5.QtWidgets import QMessageBox

def validate_stub_settings(settings):
    required_keys = [
        'enable_junk', 'min_instructions', 'max_instructions', 'use_advanced_junk',
        'enable_encryption', 'encryption_method',
        'enable_chunking', 'enable_interleaved', 'shuffle_sequence',
        'syscall_prefix_length', 'syscall_number_length', 'offset_name_length'
    ]
    for key in required_keys:
        if key not in settings:
            return False, f"Missing required setting: {key}"
    if settings['min_instructions'] < 1 or settings['min_instructions'] > 10:
        return False, "Minimum instructions must be between 1 and 10"
    if settings['max_instructions'] < 1 or settings['max_instructions'] > 20:
        return False, "Maximum instructions must be between 1 and 20"
    if settings['min_instructions'] > settings['max_instructions']:
        return False, "Minimum instructions cannot be greater than maximum instructions"
    if settings['syscall_prefix_length'] < 4 or settings['syscall_prefix_length'] > 16:
        return False, "Syscall prefix length must be between 4 and 16"
    if settings['syscall_number_length'] < 4 or settings['syscall_number_length'] > 16:
        return False, "Syscall number length must be between 4 and 16"
    if settings['offset_name_length'] < 4 or settings['offset_name_length'] > 16:
        return False, "Offset name length must be between 4 and 16"
    valid_encryption_methods = [1, 2, 3, 4, 5]
    if settings['encryption_method'] not in valid_encryption_methods:
        return False, f"Invalid encryption method: {settings['encryption_method']}"
    return True, ""

def show_validation_error(parent, message):
    QMessageBox.critical(parent, "Validation Error", message)
    
def show_validation_success(parent):
    QMessageBox.information(parent, "Validation Success", "All settings are valid!") 