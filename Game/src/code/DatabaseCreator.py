import sqlite3
from pathlib import Path
import os


class DatabaseManager:
    def __init__(self, table_name: str, list_of_params: list = [], path: str = './Database/database.db') -> None:
        """
        Function that initializes the Database Manager.

        Args:
            table_name (str): the SQL Table inside the database
            list_of_params (list, optional): All params that the SQL Table will store.
            Defaults to [].
            path (str, optional): Path to the database.
            Defaults to './sql/database.db'.
        """

        # Checks if the database file already exists, if not creates new one
        if os.path.isfile(path):
            self.__conn = sqlite3.connect(path)
        else:
            db_file = Path(path)
            db_file.parent.mkdir(exist_ok=True, parents=True)
            self.__conn = sqlite3.connect(path)

        self.__cursor = self.__conn.cursor()
        self.table_name = table_name
        self.__list_of_params = list_of_params
        self.__list_of_params_str = ", ".join(list_of_params)

        # Creates new table if the table does not exist
        self.__cursor.execute(f"CREATE TABLE IF NOT EXISTS {self.table_name}({self.__list_of_params_str});")
        self.__conn.commit()

    def get_content(self) -> list:
        """
        Function that returns a list of tuples with all the values in the SQL database's Table.

        Returns:
            list[tuple]: list of tuples with all values
        """

        res = self.__cursor.execute(f"SELECT * FROM {self.table_name};")
        print(res.fetchall())
        return res.fetchall()

    def get_cursor(self):

        return self.__cursor

    def insert(self, values: iter) -> bool:
        """
        Function that inserts values into the database

        Args:
            values (iter): values to insert, every value should match its own parameter.

        Returns:
            bool: returns True if successful, False otherwise
        """

        if len(values) != len(self.__list_of_params):
            return False

        values_str = ", ".join("'" + value + "'" for value in values)
        print(values_str)
        self.__cursor.execute(f"INSERT INTO {self.table_name} ({self.__list_of_params_str}) VALUES ({values_str});")
        self.__conn.commit()
        return True

    def insert_no_duplicates(self, values: iter, no_duplicate_params: iter) -> bool:
        """Function that inserts values into the database without duplicates of given parameters

        Args:
            values (iter): values to insert into the database
            no_duplicate_params (iter): the parameters to check if there are no duplicates of them

        Returns:
            bool: True if value has been inserted successfully, False otherwise
        """

        if len(values) != len(self.__list_of_params):
            return False

        dict_param_val = dict(map(lambda k, v: (k, v), self.__list_of_params, values))

        for no_duplicate_param in no_duplicate_params:
            if self.find(self.__list_of_params, [no_duplicate_param], [dict_param_val[no_duplicate_param]]):
                return False

        return self.insert(values)

    def find(self, return_params: iter, input_params: iter, values: iter) -> iter:
        """
        Function that finds values of given return parameters, and returns a tuple of them.
        The function accepts input parameters and values to search for their values of return parameters.
        If the satisfying input parameters and values were not found, then the function returns None.

        Args:
            return_params (iter): parameters that their values will be returned,
            input_params (iter): parameters that are used to search for desired values,
            values (iter): desired values of a row, from which the return parameters' values will be returned.

        Returns:
            iter: tuple of values according to the return parameters found or None
        """

        if len(input_params) != len(values):
            return None

        for input_param in input_params:
            if input_param not in self.__list_of_params:
                return None

        for return_param in return_params:
            if return_param not in self.__list_of_params:
                return None

        return_params_str = ", ".join(return_params)

        conditions = " AND ".join(input_param + "=?" for input_param in input_params)

        # print(conditions) #! DEBUG
        self.__cursor.execute(f"SELECT {return_params_str} FROM {self.table_name} WHERE {conditions};", values)
        res = self.__cursor.fetchone()

        return res

    def set_values(self, update_params: iter, update_values: iter,
                   condition_params: iter, condition_values: iter) -> None:

        """
        Function that sets values of some parameters to a row with column with
        matching condition values of condition parameters.

        Args:
            update_params (iter): parameters to update their values
            update_values (iter): values of parameters to update
            condition_params (iter): parameters to check if the row should be updated
            condition_values (iter): values of parameters to check if the row should be updated
        """

        if len(update_params) != len(update_values) or len(condition_params) != len(condition_values):
            return

        for param in update_params:
            if param not in self.__list_of_params:
                return

        for param in update_params:
            if param not in self.__list_of_params:
                return

        set_str = ", ".join(
            [str(update_params[i] + " = '" + update_values[i] + "'") for i in range(len(update_params))])
        print(set_str)

        where_str = " AND ".join(
            [str(condition_params[i] + " = '" + condition_values[i] + "'") for i in range(len(condition_params))])

        self.__cursor.execute(f"UPDATE {self.table_name} SET {set_str} WHERE {where_str}")
        self.__conn.commit()

    def close_conn(self) -> None:
        """
        Function that closes the connection of the Database Manager with the database itself.
        """

        self.__cursor.close()
        self.__conn.close()


def run_tests_a() -> None:
    """

    """
    main_manager = DatabaseManager("PlayerDetails", ['Username', 'Password', 'Cash', 'Status'])
    manager = DatabaseManager("PlayerDetails", ['Username', 'Password'])
    print(manager.insert_no_duplicates(["Gafhggfvfsdffgfdgrie", "12sdfs34d5"],
                                       ['Username', 'Password']))

    print(main_manager.set_values(['Cash', 'Status'], ["G33a32rie", "1343423"],
                                  ['Username', 'Password'], ["Gafhggfvfsdffgfdgrie", "12sdfs34d5"]))

    manager.close_conn()
    main_manager.close_conn()


def main() -> None:
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    run_tests_a()


if __name__ == '__main__':
    main()
