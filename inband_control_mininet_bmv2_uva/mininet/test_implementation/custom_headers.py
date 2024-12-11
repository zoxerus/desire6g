class INT_Report(Packet):
    name = 'INT_REPORT'
    fields_desc = [
        BitField(name='kind', default=1, size=8),
        BitField(name='length', default=2, size=8),
        BitField(name='init_ttl', default=3, size=8),
        BitField(name='switch_id', default=5, size=16),
        BitField(name='hop_num', default=7, size=8),
        BitField(name='trust_swid', default=11, size=16),
        BitField(name='trust_level', default=13, size=4),
        BitField(name='congestion_swid', default=17, size=16),
        BitField(name='queue_length', default=19, size=24),
        BitField(name='Pudding', default=0, size=20),
    ]
    
class INT_Report(Packet):
    name = 'INT_REPORT'
    fields_desc = [
        BitField(name='Switch_ID', default=1, size=16),
        BitField(name='Backup_Port', default=1, size=8)
    ]
