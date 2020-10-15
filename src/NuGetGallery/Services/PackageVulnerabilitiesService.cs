// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using NuGet.Services.Entities;
using NuGetGallery.Auditing;

namespace NuGetGallery
{
    public class PackageVulnerabilitiesService : IPackageVulnerabilitiesService
    {
        private readonly IEntitiesContext _entitiesContext;

        public PackageVulnerabilitiesService(IEntitiesContext entitiesContext)
        {
            _entitiesContext = entitiesContext ?? throw new ArgumentNullException(nameof(entitiesContext));
        }
        public IReadOnlyDictionary<int, IReadOnlyList<PackageVulnerability>> GetVulnerabilitiesById(string id)
        {
            var result = new Dictionary<int, List<PackageVulnerability>>();
            var rangesForId = _entitiesContext.VulnerableRanges.Where(vr => vr.PackageId == id);
            if (rangesForId == null || !rangesForId.Any())
            {
                return null;
            }

            foreach (var range in rangesForId)
            {
                if (range.Vulnerability == null)
                {
                    continue; // sanity check
                }

                foreach (var package in range.Packages)
                {
                    if (result.TryGetValue(package.Key, out var packageVulnerabilities))
                    {
                        packageVulnerabilities.Add(range.Vulnerability);
                    }
                    else
                    {
                        result.Add(package.Key, new List<PackageVulnerability> { range.Vulnerability });
                    }
                }
            }

            if (result.Count == 0)
            {
                return null;
            }

            return (IReadOnlyDictionary<int, IReadOnlyList<PackageVulnerability>>)result;
        }
    }
}