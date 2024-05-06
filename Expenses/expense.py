class Expense:

    def __init__(self, material, quantity, price, total, date, random_id=None, spreadsheet_id=None, range_name=None):
        self.material = material
        self.quantity = quantity
        self.price = price
        self.total = total
        self.date = date
        self.random_id = random_id
        self.spreadsheet_id = spreadsheet_id
        self.range_name = range_name

    def __repr__(self):
        return f"<{self.material}, {self.quantity}, {self.price}, {self.total}, {self.date}, {self.random_id}>"