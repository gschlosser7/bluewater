
nums=[0, 0, 0]
target=1
mylist=[]



nums=sorted(list(nums))
print(nums)
res=sum(nums[:3])

print(res, nums[:3])

for x in range(len(nums)-2):
    l=x+1
    r=len(nums)-1

    while l<r:
        xattempt=(nums[x]+nums[l]+nums[r])
        if abs(xattempt-target) < abs(res-target):
            res=xattempt
        if xattempt< target:
            l+=1
        else:
            r-=1
print(res)