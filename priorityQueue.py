import heapq

class PriorityQueue:
    def __init__(self):
        self.queue = []

    def push(self, priority, item):
        heapq.heappush(self.queue, (priority, item))

    def pop(self):
        return heapq.heappop(self.queue)[1]

    def is_empty(self):
        return len(self.queue) == 0

    def __len__(self):
        return len(self.queue)
